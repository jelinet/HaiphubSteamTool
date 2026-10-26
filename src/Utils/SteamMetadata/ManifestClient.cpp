#include "ManifestClient.h"
#include "OSTPlatform/include/Http.h"
#include "Utils/Config/Config.h"
#include "Utils/Config/LuaConfig.h"
#include "Utils/Logging/Log.h"

#include <algorithm>
#include <charconv>
#include <iterator>
#include <mutex>
#include <string_view>

namespace ManifestClient {

    // ── parsers ────────────────────────────────────────────────────
    using Parser = bool (*)(std::string_view body, uint64_t* out);

    static bool ParsePlainUint(std::string_view body, uint64_t* out) {
        uint64_t code = 0;
        auto [_, ec] = std::from_chars(body.data(), body.data() + body.size(), code);
        if (ec != std::errc{}) return false;
        *out = code;
        return true;
    }

    static bool ParseSteamRunJson(std::string_view body, uint64_t* out) {
        size_t key = body.find("\"content\"");
        if (key == std::string_view::npos) return false;
        size_t q1 = body.find('"', key + 9);
        if (q1 == std::string_view::npos) return false;
        size_t q2 = body.find('"', q1 + 1);
        if (q2 == std::string_view::npos) return false;
        return ParsePlainUint(body.substr(q1 + 1, q2 - q1 - 1), out);
    }

    // 20770407 实测返回纯数字 text/plain（2026-10-26，depot 3602291 / gid 1934813680967622033
    // → "8589989517436144180"）。SDM 当时 DNS 解析不到，格式未知，先按纯数字、再按 {"content":"..."} 兜底；
    // 日志会打完整 body，看到真实格式后再收紧。
    static bool ParsePlainOrContent(std::string_view body, uint64_t* out) {
        return ParsePlainUint(body, out) || ParseSteamRunJson(body, out);
    }

    // ── provider table ────────────────────────────────────────────
    //
    // Adding a new provider: add one row to kProviders below.
    // host / port / tls / path are all derived from the URL template
    // by Make() at compile time.

    struct Provider {
        std::string_view name;          // matches [manifest] url = "..."
        // gid-only form: one %llu (gid) — the pre-2026-09-09 shape.
        // nullptr for providers that have no gid-only route (20770407 / SDM answer 404).
        const char*      urlTemplate;
        // Optional depot-aware form: %u depot, %llu gid. Preferred whenever the
        // caller knows the depot, and required for correctness — see kProviders
        // below. nullptr for providers that only speak gid.
        const char*      urlTemplateEx;
        Parser           parse;
    };

    consteval Provider Make(std::string_view name, const char* url, const char* urlEx, Parser parse) {
        return {name, url, urlEx, parse};
    }

    // Valve made the request code depot-bound on 2026-09-09: it is derived from
    // (depot_id, manifest_id, time, secret), and the CDN answers 401 for a code
    // minted against any other depot. A gid-only request cannot name the depot,
    // so the server falls back to a free-to-play carrier and the resulting code
    // only works for 731/571/441 — every other depot 401s at the CDN and Steam
    // reports "Failed downloading 1 manifests".
    //
    // So the three-segment form is not an optimisation, it is the only shape
    // that works for ordinary depots. The gid-only template is kept solely as a
    // fallback for when the depot is genuinely unknown, and for the two
    // third-party providers that expose no depot-aware route.
    //
    // 2026-10-26：opensteamtool 换成 20770407（使用者要求），并新增 SDM。这两个只有
    // /manifest/{depot}/{gid} 两段路径（不带 app），没有 gid-only 路径，不知道 depot 时直接失败。
    // 先讨论过"按列表顺序逐个试、谁通用谁"，使用者最后决定保持单选（[manifest] url 选哪个用哪个）。
    static constexpr Provider kProviders[] = {
        Make("20770407",      nullptr,
                              "https://20770407.xyz/manifest/%u/%llu",           ParsePlainOrContent),
        Make("SDM",           nullptr,
                              "https://steamapi.993499094.xyz/manifest/%u/%llu", ParsePlainOrContent),
        Make("wudrm",         "http://gmrc.wudrm.com/manifest/%llu",
                              nullptr,                                           ParsePlainUint),
        Make("steamrun",      "https://manifest.steam.run/api/manifest/%llu",
                              nullptr,                                           ParseSteamRunJson),
    };

    static const Provider* g_active = &kProviders[0];   // 20770407
    static std::mutex      g_mutex;

    bool SetProvider(std::string_view name) {
        std::lock_guard<std::mutex> lock(g_mutex);
        for (const auto& p : kProviders)
            if (p.name == name) { 
                g_active = &p; 
                return true; 
            }
        return false;
    }

    const char* ActiveProviderName() {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_active->name.data(); 
    }

    // ── request ───────────────────────────────────────────────────

    void Shutdown() {
        std::lock_guard<std::mutex> lock(g_mutex);
    }

    // ── fetch ─────────────────────────────────────────────────────

    // auto 模式每个接口的超时：四个阶段加起来 10 秒（2+3+2+3），不读 [manifest] timeout_*
    // （2026-10-26 和使用者确认）。没选"每阶段各 10 秒"：那样单个接口最坏 40 秒，四个全挂要等 160 秒。
    static constexpr Config::ManifestTimeouts kAutoTimeouts{2000, 3000, 2000, 3000};

    // 用 provider p 请求一次。tryIndex / tryTotal 只用于日志（auto 模式标"第几个"，单选模式传 1/1）。
    static bool FetchFrom(const Provider& p, const Config::ManifestTimeouts& timeouts,
                          size_t tryIndex, size_t tryTotal,
                          uint64_t gid, uint64_t* outCode, AppId_t appId, AppId_t depotId) {
        // 当前 provider 的路径只有 depot/gid 两段，app 不进 URL；appId 只用于日志。
        char url[256];
        const bool depotAware = p.urlTemplateEx && depotId;
        if (depotAware) {
            std::snprintf(url, sizeof(url), p.urlTemplateEx, depotId, gid);
        } else if (p.urlTemplate) {
            std::snprintf(url, sizeof(url), p.urlTemplate, gid);
        } else {
            // 20770407 / SDM 没有 gid-only 路径；不知道 depot 就没法请求。
            LOG_MANIFEST_WARN("Manifest try {}/{} name={} needs depot but depot=0, app={} gid={}: skipped",
                              tryIndex, tryTotal, p.name, appId, gid);
            return false;
        }

        LOG_MANIFEST_INFO("Manifest try {}/{} name={} url={} app={} depot={} gid={} shape={}",
                          tryIndex, tryTotal, p.name, url, appId, depotId, gid,
                          depotAware ? "depot/gid" : "gid-only");

        auto r = OSTPlatform::Http::Execute(
            L"GET",
            url,
            nullptr,
            0,
            nullptr,
            timeouts.resolve,
            timeouts.connect,
            timeouts.send,
            timeouts.recv);

        // 完整打印返回内容（使用者要求，2026-10-26）：SDM 的返回格式还不知道，要从这里看。
        // shape 也要看：gid-only 请求拿到的 code 对普通 depot 会被 CDN 拒绝，不看日志发现不了。
        if (!r.ok || r.status != 200) {
            LOG_MANIFEST_WARN("Manifest name={} failed ok={} status={} body=\"{}\"",
                              p.name, r.ok, r.status, r.body);
            return false;
        }
        if (!p.parse(r.body, outCode)) {
            LOG_MANIFEST_WARN("Manifest name={} status=200 but parse failed body=\"{}\"", p.name, r.body);
            return false;
        }
        LOG_MANIFEST_INFO("Manifest name={} ok status=200 body=\"{}\" code={}", p.name, r.body, *outCode);
        return true;
    }

    // ── public ────────────────────────────────────────────────────

    // 实际解析逻辑；调用方已持有 g_mutex。拆出来是为了让外层在所有 return 路径上都打结束分割线。
    static bool ResolveLocked(uint64_t manifestGid, uint64_t* outRequestCode,
                              AppId_t appId, AppId_t depotId)
    {
        if (appId && depotId && LuaConfig::HasManifestCodeFuncEx()) {
            if (LuaConfig::CallManifestFetchCodeEx(appId, depotId, manifestGid, outRequestCode)) {
                LOG_MANIFEST_INFO("Manifest gid={} resolved via fetch_manifest_code_ex", manifestGid);
                return true;
            }
            LOG_MANIFEST_WARN("Manifest gid={} fetch_manifest_code_ex returned nil, trying fetch_manifest_code", manifestGid);
        }

        if (LuaConfig::HasManifestCodeFunc()) {
            if (LuaConfig::CallManifestFetchCode(manifestGid, outRequestCode)) {
                LOG_MANIFEST_INFO("Manifest gid={} resolved via manifest.lua", manifestGid);
                return true;
            }
            LOG_MANIFEST_WARN("Manifest gid={} lua returned nil, falling back to config", manifestGid);
        }

        if (!Config::GetManifestAuto())
            return FetchFrom(*g_active, Config::GetManifestTimeouts(), 1, 1,
                             manifestGid, outRequestCode, appId, depotId);

        // auto = true：按 kProviders 的顺序（20770407 → SDM → wudrm → steamrun）逐个试，成功就停。
        // 每次都从第一个开始，不记住上次成功的接口（2026-10-26 和使用者确认）。
        // 每个请求都是只读 GET，换下一个重试不会有副作用。
        constexpr size_t total = std::size(kProviders);
        for (size_t i = 0; i < total; ++i) {
            if (FetchFrom(kProviders[i], kAutoTimeouts, i + 1, total,
                          manifestGid, outRequestCode, appId, depotId)) {
                LOG_MANIFEST_INFO("Manifest gid={} resolved by {} (auto, try {}/{})",
                                  manifestGid, kProviders[i].name, i + 1, total);
                return true;
            }
        }
        LOG_MANIFEST_WARN("Manifest gid={} depot={} all {} providers failed (auto)", manifestGid, depotId, total);
        return false;
    }

    bool FetchManifestRequestCode(uint64_t manifestGid, uint64_t* outRequestCode,
                                  AppId_t appId, AppId_t depotId)
    {
        // 锁放在分割线外面：多个 depot 同时下载时，一次请求的开始线、各个 try、结束线不会和别的请求交错
        // （使用者反馈看不出哪行开始哪行结束，2026-10-26）。
        std::lock_guard<std::mutex> lock(g_mutex);
        LOG_MANIFEST_INFO("------------ Manifest START app={} depot={} gid={} auto={} ------------",
                          appId, depotId, manifestGid, Config::GetManifestAuto());
        const bool ok = ResolveLocked(manifestGid, outRequestCode, appId, depotId);
        if (ok)
            LOG_MANIFEST_INFO("------------ Manifest END   gid={} result=OK code={} ------------",
                              manifestGid, *outRequestCode);
        else
            LOG_MANIFEST_WARN("------------ Manifest END   gid={} result=FAILED ------------", manifestGid);
        return ok;
    }
}

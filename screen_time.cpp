// screen_time.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "screen_time.h"

#include "wtsapi32.h"

#include <chrono>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <string>
#include <string_view>
#include <system_error>
//#include <thread>

#include <nlohmann/json.hpp>




using namespace std;

constexpr unsigned default_screen_time_limit = 60u; // Minutes.
constexpr chrono::minutes warn_before_logout{ 2u };


std::string current_logged_in_user();

void throw_last_win32_error()
{
    error_code ec{ static_cast<int>(::GetLastError()), system_category() };
    if (ec)
        throw system_error{ ec };
}

void handle_win32_result(int result)
{
    if (result != FALSE)
        return;

    throw_last_win32_error();
}

class time_tracker_t
{
public:
    time_tracker_t();
    void update_timer(UINT_PTR, bool);

private:
    void force_logout();

    static u8string app_path();
    static nlohmann::json read_config(filesystem::path, string const&);
    static nlohmann::json read_log(filesystem::path, string const&, chrono::time_point<chrono::system_clock> const&);

    chrono::time_point<chrono::system_clock> t0_;
    chrono::seconds accumulated_;
    chrono::seconds allowed_;

    string user_name_;
    UINT_PTR timer_id_;

    filesystem::path app_path_;
    filesystem::path config_path_;
    filesystem::path log_path_;

    nlohmann::json config_;
    nlohmann::json log_;
    
};








constexpr int timer_id = 42u;
constexpr UINT timer_ellapse_millisec = 1000u;

// Global Variables and forwards.
HINSTANCE hInst;                                // Current application instance handle.
BOOL                InitInstance(HINSTANCE, int);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    // Main message loop:
    time_tracker_t tracker;
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        switch (msg.message)
        {
        case WM_TIMER:
            break;
        }
    }

    return (int) msg.wParam;
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance;
   /*handle_win32_result(*/::SetTimer(nullptr, timer_id, timer_ellapse_millisec, nullptr)/*)*/;

   return TRUE;
}

std::string current_logged_in_user()
{
    PWTS_SESSION_INFOA sessions = nullptr;
    DWORD session_count = 0u;
    handle_win32_result(::WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0u, 1u, &sessions, &session_count));

    for (auto session = sessions; session != sessions + session_count; ++session)
    {
        if (session->State != WTSActive)
            continue;
        
        LPSTR buffer = nullptr;
        DWORD bytes = 0u;
        handle_win32_result(::WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, session->SessionId, WTS_INFO_CLASS::WTSUserName, &buffer, &bytes));

        return string{ buffer };
    }

    return "n/a";
}

time_tracker_t::time_tracker_t()
    : t0_(chrono::system_clock::now())
    , accumulated_(0u)
    , allowed_(0u)
    , user_name_(current_logged_in_user())
    , timer_id_(0u)
    , app_path_(app_path())
    , config_path_(app_path() + u8string{ u8"config.json" })
    , log_path_(app_path() + u8string{ u8"log.json" })
{
    config_ = read_config(config_path_, user_name_);
    log_ = read_log(log_path_, user_name_, t0_);

    accumulated_ = chrono::duration_cast<chrono::seconds>(chrono::minutes{ log_[user_name_]["minutes"] });
    allowed_ = chrono::duration_cast<chrono::seconds>(chrono::minutes{ config_[user_name_] });
}


void time_tracker_t::update_timer(UINT_PTR timer_id , bool unlocking)
{
    if (timer_id != timer_id_)
        return;

    if (timer_id_ != 0u)
    {
        handle_win32_result(::KillTimer(nullptr, timer_id_));
    }

    // Update timing
    auto now = chrono::system_clock::now();
    if (unlocking)
        t0_ = now; // Don't count time while screen was locked!

    auto ellapsed = now - t0_;
    accumulated_ += chrono::ceil<chrono::seconds>(ellapsed);

    // Handle immediate logout!
    if (accumulated_ >= allowed_)
    {
        force_logout();
        return;
    }

    // Handle logout warning.
    auto left = allowed_ - accumulated_;
    if (chrono::ceil<chrono::minutes>(left) <= warn_before_logout)
    {
        string msg = format("User {} has used up screen time for today and will be logged out in less than {}", user_name_, warn_before_logout);
        async(launch::async, [msg]()
        {
            ::MessageBoxA(nullptr, msg.c_str(), "Logout Warning", MB_OK | MB_ICONWARNING);
        });
    }
    else
    {
        left -= warn_before_logout;
    }

    // Handle timer update.
    chrono::milliseconds timer_amount = chrono::duration_cast<chrono::milliseconds>(left);
    timer_id_ = ::SetTimer(nullptr, timer_id_, timer_amount.count(), nullptr);
    if (timer_id_ == 0u)
        throw_last_win32_error();
}

void time_tracker_t::force_logout()
{
    
}

u8string time_tracker_t::app_path()
{
    filesystem::path app_path;
    char const* appdata = ::getenv("APPDATA");
    if (appdata)
    {
        app_path = filesystem::path(appdata);
        app_path += filesystem::path::preferred_separator;
    }
    app_path += filesystem::path{"screen_time"};

    return app_path.u8string();
}

nlohmann::json time_tracker_t::read_config(filesystem::path file, string const &user)
{
    nlohmann::json config;
    ifstream config_file{ file };
    if (config_file.is_open())
    {
        config_file >> config;
    }
    if (!config.contains(user))
    {
        config[user] = default_screen_time_limit;
    }

    return config;
}

nlohmann::json time_tracker_t::read_log(filesystem::path file, string const &user, chrono::time_point<chrono::system_clock> const &t0)
{
    nlohmann::json log;
    std::string const today = std::format("{0}", chrono::year_month_day{ chrono::floor<chrono::days>(t0) });
    ifstream log_file{ file };
    if (log_file.is_open())
    {
        log_file >> log;
    }
    if (!log.contains(user))
    {
        log[user]["date"] = today;
        log[user]["minutes"] = 0u;
    }
    else if (today != log[user]["date"])
    {
        log[user]["date"] = today;
        log[user]["minutes"] = 0u;
    }

    return log;
}
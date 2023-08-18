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

constexpr wchar_t const* window_class_name = L"__screen_time__";




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
    time_tracker_t(HWND);
    void update_timer(UINT_PTR);
    void locked();
    void unlocked();

private:
    chrono::seconds append_ellapsed_time();
    chrono::seconds handle_lagout_warning();
    void force_lock_screen();

    static u8string app_path();
    static void create_app_folder(filesystem::path const&);
    static nlohmann::json read_config(filesystem::path const&, string const&);
    static nlohmann::json read_log(filesystem::path const&, string const&, chrono::time_point<chrono::system_clock> const&);
    static void write_json(filesystem::path const&, nlohmann::json const&);

    HWND hwnd_;
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

constexpr int c_timer_id = 42u;
constexpr UINT timer_ellapse_millisec = 1000u;

// Global Variables and forwards.
HINSTANCE hInst;                                // Current application instance handle.
HWND                InitInstance(HINSTANCE, ATOM);
ATOM RegisterCustomWindow(HINSTANCE);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Perform application initialization:
    ATOM atom = RegisterCustomWindow(hInstance);
    HWND hWnd = InitInstance(hInstance, atom);
    handle_win32_result(::WTSRegisterSessionNotification(hWnd, NOTIFY_FOR_ALL_SESSIONS));

    // Main message loop:
    time_tracker_t tracker{ hWnd };
    tracker.update_timer(c_timer_id);
    
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        switch (msg.message)
        {
        case WM_TIMER:
            tracker.update_timer(msg.wParam); 
            break;

        case WM_WTSSESSION_CHANGE:
            if (msg.wParam == WTS_SESSION_LOCK)
                tracker.locked();
            if (msg.wParam == WTS_SESSION_UNLOCK)
                tracker.unlocked();
            break;
        }
    }

    handle_win32_result(::WTSUnRegisterSessionNotification(hWnd));
    return (int) msg.wParam;
}

HWND InitInstance(HINSTANCE hInstance, ATOM atom)
{
   hInst = hInstance;
   HWND hWnd = CreateWindowW(window_class_name, nullptr, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);
   if (hWnd == nullptr)
   {
       throw_last_win32_error();
   }

   handle_win32_result(::ShowWindow(hWnd, SW_HIDE));
   return hWnd;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
    {
        bool break_here = false;
        int wmId = LOWORD(wParam);
        switch (wmId)
        {
        case IDM_EXIT:
            ::DestroyWindow(hWnd);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

ATOM RegisterCustomWindow(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;
    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_NOCLOSE;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = nullptr;
    wcex.hCursor = nullptr;
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = nullptr;
    wcex.lpszClassName = window_class_name;
    wcex.hIconSm = nullptr;

    return ::RegisterClassExW(&wcex);
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

time_tracker_t::time_tracker_t(HWND hwnd)
    : hwnd_(hwnd)
    , t0_(chrono::system_clock::now())
    , accumulated_(0u)
    , allowed_(0u)
    , user_name_(current_logged_in_user())
    , timer_id_(0u)
    , app_path_(app_path())
    , config_path_(app_path() + u8string{ u8"\\config.json" })
    , log_path_(app_path() + u8string{ u8"\\log.json" })
{
    create_app_folder(app_path_);
    config_ = read_config(config_path_, user_name_);
    log_ = read_log(log_path_, user_name_, t0_);
    write_json(config_path_, config_);

    accumulated_ = chrono::duration_cast<chrono::seconds>(chrono::minutes{ log_[user_name_]["minutes"] });
    allowed_ = chrono::duration_cast<chrono::seconds>(chrono::minutes{ config_[user_name_] });
}


void time_tracker_t::update_timer(UINT_PTR timer_id)
{
    if (timer_id_ != 0u)
    {
        handle_win32_result(::KillTimer(hwnd_, timer_id_));
    }
    else // (timer_id_ == 0u)
    {
        timer_id_ = timer_id;
    }

    // Handle append ellapsed time and timer update.
    auto left = append_ellapsed_time();
    chrono::milliseconds timer_amount = chrono::duration_cast<chrono::milliseconds>(left);
    UINT_PTR result = ::SetTimer(hwnd_, timer_id_, static_cast<UINT>(timer_amount.count()), nullptr);
    if (result == FALSE)
        throw_last_win32_error();
}

void time_tracker_t::locked()
{
    append_ellapsed_time();
}

void time_tracker_t::unlocked()
{
    auto now = chrono::system_clock::now();
    t0_ = now;
    update_timer(timer_id_);
}

chrono::seconds time_tracker_t::append_ellapsed_time()
{
    auto now = chrono::system_clock::now();
    auto ellapsed = now - t0_;
    t0_ = now;
    accumulated_ += chrono::ceil<chrono::seconds>(ellapsed);
    log_[user_name_]["minutes"] = chrono::floor<chrono::minutes>(accumulated_).count();
    write_json(log_path_, log_);

    // Handle immediate logout!
    if (accumulated_ >= allowed_)
    {
        force_lock_screen();
        return chrono::seconds{ 0u };
    }

    return handle_lagout_warning();
}

chrono::seconds time_tracker_t::handle_lagout_warning()
{
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

    return left;
}

void time_tracker_t::force_lock_screen()
{
    handle_win32_result(::LockWorkStation());
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

void time_tracker_t::create_app_folder(filesystem::path const& path)
{
    if (filesystem::exists(path))
        return;

    filesystem::create_directories(path);
}

nlohmann::json time_tracker_t::read_config(filesystem::path const &file, string const &user)
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

nlohmann::json time_tracker_t::read_log(filesystem::path const &file, string const &user, chrono::time_point<chrono::system_clock> const &t0)
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

void time_tracker_t::write_json(filesystem::path const &file, nlohmann::json const &json)
{
    ofstream out_file{ file };
    if (!out_file.is_open())
        throw std::runtime_error{ format("failed to open {} for writing", file.generic_string()) };
    
    out_file << json;
}
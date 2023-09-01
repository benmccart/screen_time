// screen_time.cpp : Defines the entry point for the application.
//

#define NOMINMAX 1

#include "framework.h"
#include "screen_time.h"

#include "wtsapi32.h"

#include <chrono>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <string>
#include <string_view>
#include <system_error>
//#include <thread>

#include <nlohmann/json.hpp>

constexpr wchar_t const* window_class_name = L"__screen_time__";




using namespace std;

constexpr unsigned default_screen_time_limit = 60u; // Minutes.
constexpr chrono::minutes warn_before_logout{ 2u };
constexpr chrono::seconds timer_step{ 60u };

struct user_t
{
    std::string name;
    DWORD session_id = 0u;
};

user_t current_logged_in_user();
static std::u8string app_path();
static std::u8string config_path();
void create_folder(filesystem::path const&);

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

class log_redirect_t
{
public:
    log_redirect_t();
    ~log_redirect_t();

private:
    std::streambuf* original_;
    std::ofstream logfile_;
};

class time_tracker_t
{
public:
    time_tracker_t(HWND);
    void update_timer(UINT_PTR);
    void locked();
    void unlocked();

private:
    struct user_record_t
    {
        chrono::seconds accumulated = chrono::seconds{ 0u };
        chrono::seconds allowed = chrono::seconds{ 0u };
        user_t user;
    };
    using user_records_t = std::map<std::string, user_record_t>;

    chrono::seconds append_ellapsed_time();
    chrono::seconds handle_logout_warning(user_record_t const&);
    void force_lock_screen();
    user_record_t& user_record(std::string const&);
    chrono::seconds allowed_user_time(std::string const&) const;

    static nlohmann::json read_config(filesystem::path const&);
    user_records_t read_cache(filesystem::path const&) const;
    static void write_json(filesystem::path const&, nlohmann::json const&);
    void cache_user_records() const;
    

    HWND hwnd_;
    chrono::time_point<chrono::system_clock> t0_;

    std::map<std::string, user_record_t> user_records_;

    user_t current_user_;
    UINT_PTR timer_id_;

    filesystem::path app_path_;
    filesystem::path config_path_;
    filesystem::path cache_path_;

    nlohmann::json config_;
    std::vector<std::future<void>> futures_;
    

};

constexpr int c_timer_id = 42u;
constexpr UINT timer_ellapse_millisec = 1000u;

// Global Variables and forwards.
HINSTANCE hInst; // Current application instance handle.
HWND InitInstance(HINSTANCE, ATOM);
ATOM RegisterCustomWindow(HINSTANCE);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

	try
	{
        std::clog << "begin wWinMain(...)" << std::endl;
		log_redirect_t redirect{};

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
			{
				tracker.update_timer(msg.wParam);
			}
			break;

			case WM_WTSSESSION_CHANGE:
			{
				switch (msg.wParam)
				{
				case WTS_SESSION_LOCK:
                case WTS_SESSION_LOGOFF:
                case WTS_REMOTE_DISCONNECT:
                case WTS_SESSION_TERMINATE:
					tracker.locked();
					break;

				case WTS_SESSION_UNLOCK:
                case WTS_SESSION_LOGON:
                case WTS_REMOTE_CONNECT:
					tracker.unlocked();
					break;
				}
			}
            break;

			case WM_ENDSESSION:
			case WM_QUERYENDSESSION:
				tracker.locked();
				break;
			}
        }

        handle_win32_result(::WTSUnRegisterSessionNotification(hWnd));

    }
    catch (std::exception const& ex)
    {
        string log_file;
        char const* appdata = ::getenv("APPDATA");
        if (appdata)
        {
            log_file = appdata;
            log_file += "\\screen_time\\error.txt";
        }
        else
        {
            log_file = "C:\\screen_time_error_log.txt";
        }
        ofstream ofs{ log_file };
        ofs << ex.what();
        return -1;
    }

    return 0;
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
            std::clog << "IDM_EXIT" << std::endl;
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
        }
    }
    break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        std::clog << "WM_DESTROY" << std::endl;
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

user_t current_logged_in_user()
{
    user_t user;
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

        user_t user;
        user.name = buffer;
        user.session_id = session->SessionId;
        return user;
    }

    return user_t{};
}

u8string app_path()
{
    filesystem::path result;
    char const* appdata = ::getenv("APPDATA");
    if (appdata)
    {
        result = filesystem::path{ appdata };
        result += filesystem::path::preferred_separator;
    }
    result += filesystem::path{"screen_time"};

    return result.u8string();
}

u8string config_path()
{
    filesystem::path result;
    std::array<char, 512> buffer;
    int bytes = ::GetModuleFileNameA(nullptr, buffer.data(), buffer.size());
    if (bytes > 0)
    {
        result = filesystem::path{ buffer.data() };
        result = result.parent_path();
    }

    return result.u8string();
}

void create_folder(filesystem::path const& path)
{
    if (filesystem::exists(path))
        return;

    filesystem::create_directories(path);
}

log_redirect_t::log_redirect_t()
    : original_(std::clog.rdbuf())
{
    filesystem::path path = app_path();
    create_folder(path);
    path += "\\log.txt";

    if (filesystem::exists(path))
        filesystem::remove(path);

    logfile_.open(path);
    if (logfile_.is_open())
        std::clog.rdbuf(logfile_.rdbuf());
    else
        original_ = nullptr;
}

log_redirect_t::~log_redirect_t()
{
    if (original_)
    {
        std::clog.rdbuf(original_);
        std::clog.flush();
    }
}

time_tracker_t::time_tracker_t(HWND hwnd)
    : hwnd_(hwnd)
    , t0_(chrono::system_clock::now())
    , timer_id_(0u)
    , app_path_(app_path())
    , config_path_(config_path() + u8string{ u8"\\config.json" })
    , cache_path_(app_path() + u8string{ u8"\\cache.json" })
{
    config_ = read_config(config_path_);
    user_records_ = read_cache(cache_path_);
    futures_.reserve(128);
}


void time_tracker_t::update_timer(UINT_PTR timer_id)
{
    if (current_user_.name.empty())
        return;

    if (timer_id_ != 0u)
    {
        handle_win32_result(::KillTimer(hwnd_, timer_id_));
    }
    else // (timer_id_ == 0u)
    {
        timer_id_ = timer_id;
    }

    // Handle append ellapsed time and timer update.
    auto next = append_ellapsed_time();
    chrono::milliseconds timer_amount = chrono::duration_cast<chrono::milliseconds>(next);
    UINT_PTR result = ::SetTimer(hwnd_, timer_id_, static_cast<UINT>(timer_amount.count()), nullptr);
    if (result == FALSE)
        throw_last_win32_error();

    std::clog << "Timer set for '" << next << "' in the future." << std::endl;
}

void time_tracker_t::locked()
{
    if (current_user_.name.empty())
        current_user_ = current_logged_in_user();

    std::clog << "Workstation locked for '" << current_user_.name << "'" << std::endl;
    append_ellapsed_time();
    current_user_ = user_t{};
}

void time_tracker_t::unlocked()
{
    current_user_ = current_logged_in_user();
    std::clog << "Workstation unlocked for '" << current_user_.name << "'" << std::endl;
    auto now = chrono::system_clock::now();
    t0_ = now;
    update_timer(timer_id_);
}

chrono::seconds time_tracker_t::append_ellapsed_time()
{
    assert(!current_user_.name.empty());
    auto now = chrono::system_clock::now();
    auto ellapsed = now - t0_;
    t0_ = now;

    user_record_t& record = user_record(current_user_.name);
    record.accumulated += chrono::ceil<chrono::seconds>(ellapsed);
    cache_user_records();

    // Handle immediate logout!
    if (record.accumulated >= record.allowed)
    {
        force_lock_screen();
        return chrono::seconds{ 0u };
    }

    return handle_logout_warning(record);
}

chrono::seconds time_tracker_t::handle_logout_warning(user_record_t const &record)
{
    auto warn_fun = [&]( chrono::seconds remaining)
    {
        DWORD session_id = current_user_.session_id;
        string msg = format("User {} has used up screen time for today and will be logged out in {}", current_user_.name, remaining);
        std::clog << msg << std::endl;
        std::future<void> future = async(launch::async, [msg, session_id]()
        {
             HANDLE hToken = nullptr;
             if (!::WTSQueryUserToken(session_id, &hToken))
             {
                 std::error_code ec{ static_cast<int>(::GetLastError()), std::system_category() };
                 std::clog << "ERROR: Failed to get user token (" << ec.value() << ") '" << ec.message() << "'" << std::endl;
                 return;
             }
             
             if (!::ImpersonateLoggedOnUser(hToken))
             {
                 std::error_code ec{ static_cast<int>(::GetLastError()), std::system_category() };
                 std::clog << "ERROR: Failed to impersonate logged in user (" << ec.value() << ") '" << ec.message() << "'" << std::endl;
                 return;
             }

             ::MessageBoxA(nullptr, msg.c_str(), "Logout Warning", MB_OK | MB_ICONWARNING);
        });

        futures_.push_back(std::move(future));
		auto itr = std::remove_if(std::begin(futures_), std::end(futures_), [](std::future<void>& fut)
		{
			if (fut.wait_for(std::chrono::milliseconds{ 0 }) == std::future_status::ready)
    		{
	    		fut.get();
		    	return true;
		    }

				return false;
		});
        futures_.erase(itr, std::end(futures_));
    };
    if (record.accumulated > record.allowed)
    {
        warn_fun(chrono::seconds { 1u });
        return chrono::seconds { 1u };
    }

    auto left = record.allowed - record.accumulated;
    if (chrono::ceil<chrono::minutes>(left) <= warn_before_logout)
    {
        warn_fun(left);
    }

    auto next = std::min(left, timer_step);
    return next;
}

void time_tracker_t::force_lock_screen()
{
    std::clog << "Logging out '" << current_user_.name << "'" << std::endl;

    HANDLE hToken = nullptr;
    handle_win32_result(::WTSQueryUserToken(current_user_.session_id, &hToken));
    handle_win32_result(::ImpersonateLoggedOnUser(hToken));
    handle_win32_result(::ExitWindowsEx(EWX_LOGOFF, 0xFFFFFFFF)); // EWX_FORCE ???
    handle_win32_result(::RevertToSelf());
    std::clog << "Logged out success" << std::endl;
}

time_tracker_t::user_record_t& time_tracker_t::user_record(std::string const &user)
{
    if (!user_records_.contains(user))
    {
        user_record_t record;
        record.allowed = allowed_user_time(user);
        user_records_[user] = record;
    }

    return user_records_[user];
}

chrono::seconds time_tracker_t::allowed_user_time(std::string const &user) const
{
    chrono::minutes minutes = (config_.contains(user)) ? chrono::minutes{ static_cast<unsigned>(config_[user]) } : chrono::minutes{ default_screen_time_limit };
    return chrono::duration_cast<chrono::seconds>(minutes);
}

nlohmann::json time_tracker_t::read_config(filesystem::path const &file)
{
    std::clog << "reading config from: " << file << std::endl;
    nlohmann::json config;
    ifstream config_file{ file };
    if (config_file.is_open())
    {
        config_file >> config;
    }
    else
    {
        std::clog << "Error: failed to open json file for reading: " << file << std::endl;
    }
    return config;
}

time_tracker_t::user_records_t time_tracker_t::read_cache(filesystem::path const &file) const
{
    user_records_t records;
    nlohmann::json cache;

    std::clog << "reading cache from: " << file << std::endl;
    std::string const today = std::format("{0}", chrono::year_month_day{ chrono::floor<chrono::days>(chrono::system_clock::now()) });
    {
        ifstream log_file{ file };
        if (log_file.is_open())
        {
            log_file >> cache;
        }
        else
        {
            std::clog << "Error: failed to open json file for reading: " << file << std::endl;
        }
    }

    for (auto& [user, config] : config_.items())
    {
        if (!cache.contains(user))
        {
            cache[user]["date"] = today;
            cache[user]["minutes"] = 0u;
        }
        else if (today != cache[user]["date"])
        {
            cache[user]["date"] = today;
            cache[user]["minutes"] = 0u;
        }
    }

    for (auto& [user, args] : cache.items())
    {
        user_record_t record;
        record.allowed = allowed_user_time(user);
        chrono::minutes accu_minutes = chrono::minutes{ static_cast<unsigned>(cache[user]["minutes"]) };
        record.accumulated = chrono::duration_cast<chrono::seconds>(accu_minutes);
        records[user] = record;
    }

    return records;
}

void time_tracker_t::write_json(filesystem::path const &file, nlohmann::json const &json)
{
    ofstream out_file{ file };
    if (out_file.is_open())
    {
        out_file << json << std::endl;
    }
    else
    {
        std::clog << "Error: failed to open json file for writing: " << file << std::endl;
    }
}

void time_tracker_t::cache_user_records() const
{
    nlohmann::json cache;
    for (auto& [user, record] : user_records_)
    {
        cache[user]["minutes"] = chrono::duration_cast<chrono::minutes>(record.accumulated).count();
    }
    write_json(cache_path_, cache);
}
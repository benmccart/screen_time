// screen_time.cpp : Defines the entry point for the application.
//

#define NOMINMAX 1

#include "framework.h"
#include "screen_time.h"

#include "accctrl.h"
#include "aclapi.h"
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

#include <nlohmann/json.hpp>

constexpr wchar_t const* window_class_name = L"__screen_time__";
constexpr LPCSTR reg_cache_key = "SOFTWARE\\screen_time";
constexpr LPCSTR reg_cache_minutes = "minutes";
constexpr LPCSTR reg_cache_seconds = "seconds";
constexpr LPCSTR reg_cache_date = "date";

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
std::u8string app_path();
std::u8string config_path();
void create_folder(filesystem::path const&);
void make_process_protected();

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

void handle_registry_result(int result)
{
    if (result == ERROR_SUCCESS)
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
        std::string date;
        user_t user;
    };
    
    struct reg_key_closer_t
    {
        using pointer = HKEY;
        void operator()(HKEY key) const { ::RegCloseKey(key); }
    };
    using regkey_ptr = std::unique_ptr<HKEY, reg_key_closer_t>;

    chrono::seconds append_ellapsed_time();
    chrono::seconds handle_logout_warning(user_record_t const&);
    void force_lock_screen();
    chrono::seconds allowed_user_time(std::string const&) const;
    static std::string today();
    static std::string today(chrono::system_clock::time_point const&);

    static nlohmann::json read_config(filesystem::path const&);
    user_record_t read_cache() const;
    static void write_json(filesystem::path const&, nlohmann::json const&);
    void cache_user_record() const;
    

    HWND hwnd_;
    chrono::time_point<chrono::system_clock> t0_;

    user_record_t record_;
    UINT_PTR timer_id_;

    filesystem::path app_path_;
    filesystem::path config_path_;

    nlohmann::json config_;
    std::vector<std::future<void>> futures_;
    bool logged_out_ = false;
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
        log_redirect_t redirect{};
        std::clog << "redirected log" << std::endl;
        make_process_protected();
        std::clog << "made process protected" << std::endl;
		

		// Perform application initialization:
		ATOM atom = RegisterCustomWindow(hInstance);
		HWND hWnd = InitInstance(hInstance, atom);
		handle_win32_result(::WTSRegisterSessionNotification(hWnd, NOTIFY_FOR_ALL_SESSIONS));

		// Main message loop:
        std::clog << "registered notify for all sessions" << std::endl;
		time_tracker_t tracker{ hWnd };
        std::clog << "init tracker" << std::endl;
		tracker.update_timer(c_timer_id);
        std::clog << "update timer" << std::endl;

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
    int bytes = ::GetModuleFileNameA(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
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

void make_process_protected()
{
    struct handle_closer_t
    {
        using pointer = HANDLE;
        void operator()(HANDLE handle) const { ::CloseHandle(handle); }
    };
    using handle_ptr = std::unique_ptr<HANDLE, handle_closer_t>;

    struct acl_free_t
    {
        using pointer = PACL;
        void operator()(PACL acl) const { ::LocalFree(acl); }
    };
    using acl_ptr = std::unique_ptr<PACL, acl_free_t>;

    EXPLICIT_ACCESS_A denyAccess = { 0 };
    constexpr DWORD dwAccessPermissions = GENERIC_WRITE | PROCESS_ALL_ACCESS | WRITE_DAC | DELETE | WRITE_OWNER | READ_CONTROL;
    std::string user = "CURRENT_USER";
    ::BuildExplicitAccessWithNameA(&denyAccess, user.data(), dwAccessPermissions, DENY_ACCESS, NO_INHERITANCE);
    
    PACL p_acl = nullptr;
    if (::SetEntriesInAclA(1, &denyAccess, nullptr, &p_acl) != ERROR_SUCCESS)
    {
        throw_last_win32_error();
    }
    acl_ptr acl{ p_acl };

    handle_ptr process{ ::GetCurrentProcess() };
    if (::SetSecurityInfo(process.get(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, acl.get(), nullptr) != ERROR_SUCCESS)
        throw_last_win32_error();
}

log_redirect_t::log_redirect_t()
    : original_(std::clog.rdbuf())
{
    std::cerr << "log redirect" << std::endl;
    filesystem::path path = app_path();
    std::cerr << "redirect path: " << path << std::endl;

    create_folder(path);
    path += "\\log.txt";

    std::cerr << "log path: " << path << std::endl;

    if (filesystem::exists(path))
        filesystem::remove(path);

    logfile_.open(path);
    if (logfile_.is_open())
        std::clog.rdbuf(logfile_.rdbuf());
    else
        original_ = nullptr;

    std::cerr << "log redirect complete" << std::endl;
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
{
    config_ = read_config(config_path_);
    record_ = read_cache();
    futures_.reserve(128);
}


void time_tracker_t::update_timer(UINT_PTR timer_id)
{
    if (timer_id_ != 0u)
    {
        ::KillTimer(hwnd_, timer_id_);
    }
    if (timer_id_ == 0u)
    {
        timer_id_ = timer_id;
    }

    if (logged_out_ == true)
    {
        timer_id_ = 0u;
        return; // Bail out!
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
    std::clog << "Workstation locked (" << chrono::system_clock::now() << ")" << std::endl;
    append_ellapsed_time();

    auto current_user = current_logged_in_user();
    if (current_user.name == record_.user.name)
        logged_out_ = true;
}

void time_tracker_t::unlocked()
{
    auto current_user = current_logged_in_user();
    if (current_user.name == record_.user.name)
        logged_out_ = false;

    auto now = chrono::system_clock::now();
    std::clog << "Workstation unlocked (" << now << ")" << std::endl;
    t0_ = now;
    update_timer(timer_id_);
}

chrono::seconds time_tracker_t::append_ellapsed_time()
{
    auto current_user = current_logged_in_user();
    if (current_user.name != record_.user.name)
    {
        std::clog << "timed user is '" << record_.user.name << "' but current user is '" << current_user.name << "'" << std::endl;
        return chrono::minutes{ 1 };
    }

    auto now = chrono::system_clock::now();
    auto ellapsed = now - t0_;
    t0_ = now;

    record_.accumulated += chrono::ceil<chrono::seconds>(ellapsed);
    std::string const date = today(now);
    if (record_.date != date)
    {
        std::clog << "reset date from '" << record_.date << "' to '" << date << "' (" << date << ")" << std::endl;
        record_.accumulated = chrono::seconds{ 0u };
        record_.date = date;
    }
    cache_user_record();

    // Handle immediate logout!
    if (record_.accumulated >= record_.allowed)
    {
        force_lock_screen();
        return chrono::seconds{ 0u };
    }

    return handle_logout_warning(record_);
}

chrono::seconds time_tracker_t::handle_logout_warning(user_record_t const &record)
{
    auto warn_fun = [&]( chrono::seconds remaining)
    {
        string msg = format("User {} has used up screen time for today and will be logged out in {}", record_.user.name, remaining);
        std::clog << msg << std::endl;
        std::future<void> future = async(launch::async, [msg]()
        {
            HWND hDesktop = ::GetDesktopWindow();
            ::MessageBoxA(hDesktop, msg.c_str(), "Logout Warning", MB_OK | MB_ICONWARNING);
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

    std::clog << "Locking Screen" << std::endl;
    handle_win32_result(::LockWorkStation());
    std::clog << "Screen Locked" << std::endl;
}

chrono::seconds time_tracker_t::allowed_user_time(std::string const& name) const
{
    chrono::minutes minutes = (config_.contains(name)) ? 
        chrono::minutes{ static_cast<unsigned>(config_[name]) } : 
        chrono::minutes{ default_screen_time_limit };
    return chrono::duration_cast<chrono::seconds>(minutes);
}

std::string time_tracker_t::today()
{
    return today(chrono::system_clock::now());
}

std::string time_tracker_t::today(chrono::system_clock::time_point const &now)
{
    const std::chrono::zoned_time zt{ std::chrono::current_zone(), now };
    return std::format("{0}", chrono::year_month_day{ chrono::floor<chrono::days>(zt.get_local_time()) });
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

time_tracker_t::user_record_t time_tracker_t::read_cache() const
{
    user_record_t record;
    DWORD reg_minutes = 0u;
    DWORD reg_seconds = 0u;
    DWORD data_size = sizeof(DWORD);
    LSTATUS status = ::RegGetValueA(HKEY_CURRENT_USER, reg_cache_key, reg_cache_minutes, RRF_RT_REG_DWORD, nullptr, &reg_minutes, &data_size);
    if (status == ERROR_SUCCESS)
    {
        record.accumulated = chrono::duration_cast<chrono::seconds>(chrono::minutes{ reg_minutes });
    }
    data_size = sizeof(DWORD);
    status = ::RegGetValueA(HKEY_CURRENT_USER, reg_cache_key, reg_cache_minutes, RRF_RT_REG_DWORD, nullptr, &reg_seconds, &data_size);
    if (status == ERROR_SUCCESS)
    {
        record.accumulated += chrono::seconds{ reg_seconds };
    }

    std::array<char, 64u> buffer;
    data_size = static_cast<DWORD>(buffer.size());
    status = ::RegGetValueA(HKEY_CURRENT_USER, reg_cache_key, reg_cache_date, RRF_RT_REG_SZ, nullptr, buffer.data(), &data_size);
    if (status == ERROR_SUCCESS)
    {
        record.date = buffer.data();
    }
    std::string const date = today();
    if (record.date != date)
    {
        record.accumulated = chrono::seconds{ 0u };
        record.date = date;
    }

    record.user = current_logged_in_user();
    record.allowed = allowed_user_time(record.user.name);
    return record;
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

void time_tracker_t::cache_user_record() const
{

    HKEY reg_key = nullptr;
    LSTATUS status = ::RegOpenKeyA(HKEY_CURRENT_USER, reg_cache_key, &reg_key);
    if (status != ERROR_SUCCESS)
    {
        handle_registry_result(::RegCreateKeyA(HKEY_CURRENT_USER, reg_cache_key, &reg_key));
    }
    regkey_ptr key{ reg_key };

    DWORD const minutes = static_cast<DWORD>(chrono::duration_cast<chrono::minutes>(record_.accumulated).count());
    handle_registry_result(::RegSetValueExA(key.get(), reg_cache_minutes, 0u, REG_DWORD, static_cast<BYTE const*>(static_cast<void const*>(&minutes)), sizeof(minutes)));

    DWORD const seconds = static_cast<DWORD>((record_.accumulated - chrono::duration_cast<chrono::seconds>(chrono::minutes{ minutes })).count());
    handle_registry_result(::RegSetValueExA(key.get(), reg_cache_seconds, 0u, REG_DWORD, static_cast<BYTE const*>(static_cast<void const*>(&seconds)), sizeof(minutes)));

    handle_registry_result(::RegSetValueExA(key.get(), reg_cache_date, 0u, REG_SZ, static_cast<BYTE const*>(static_cast<void const*>(record_.date.data())), static_cast<DWORD>(record_.date.size() + 1u)));

    std::clog << " cache content -- date:'" << record_.date << "' minutes:" << minutes << " seconds:" << seconds << " (" << chrono::system_clock::now() << ")" << std::endl;
}
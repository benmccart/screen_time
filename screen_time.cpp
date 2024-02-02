// screen_time.cpp : Defines the entry point for the application.
//

#define NOMINMAX 1

#include "framework.h"
#include "screen_time.h"

#include "accctrl.h"
#include "aclapi.h"
#include "wtsapi32.h"

#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
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
constexpr chrono::seconds warn_before_logout{ 180u };
constexpr chrono::seconds timer_step{ 60u };

struct user_t
{
    std::string name;
    DWORD session_id = std::numeric_limits<DWORD>::max();
};

user_t get_user(DWORD);
std::u8string app_path();
std::u8string app_path();
void create_folder(filesystem::path const&);
void make_process_protected();

void log_file_location_for_exception(char const* const szfile, int line)
{
    std::clog << "throwing exception from " << szfile << " (" << line << ")" << std::endl;
}

void throw_last_win32_error(char const*const szFile, int line)
{
    log_file_location_for_exception(szFile, line);
    error_code ec{ static_cast<int>(::GetLastError()), system_category() };
    if (ec)
        throw system_error{ ec };
}

void handle_win32_result(int result, char const*const szFile, int line)
{
    if (result != FALSE)
        return;

    throw_last_win32_error(szFile, line);
}

class log_redirect_t
{
public:
    log_redirect_t();
    ~log_redirect_t();

private:
    std::streambuf* original_;
    std::fstream logfile_;
};


class time_tracker_t
{
public:
    time_tracker_t(HWND);
    void update_timer(UINT_PTR);
    void session_suspend(DWORD);
    void session_resume(DWORD);

private:
    struct user_record_t
    {
        chrono::seconds accumulated = chrono::seconds{ 0u };
        chrono::seconds allowed = chrono::seconds{ 0u };
        std::string date;
        user_t user;

        UINT_PTR timer_id = 0;
        bool logged_in = false;
    };
    using user_records_t = std::map<std::string, user_record_t>;
    
    struct reg_key_closer_t
    {
        using pointer = HKEY;
        void operator()(HKEY key) const { ::RegCloseKey(key); }
    };
    using regkey_ptr = std::unique_ptr<HKEY, reg_key_closer_t>;

    chrono::seconds append_ellapsed_time();
    user_t get_user(DWORD sessionId) const;
    
    void force_logout(user_t const&);

    void cache_user_records() const;
    void update_logged_in_users();
    
    static void send_logout_warning(user_t const&, std::chrono::seconds);
    static void send_msg(user_t const&, std::string const&);
    static std::string today();
    static std::string today(chrono::system_clock::time_point const&);
    static user_records_t read_cache(nlohmann::json const&, nlohmann::json const&);
    static nlohmann::json read_json(filesystem::path const&);
    static void write_json(filesystem::path const&, nlohmann::json const&);

    HWND hwnd_;
    chrono::time_point<chrono::system_clock> t0_;
    DWORD timer_id_ = 0u;

    filesystem::path config_path_;
    filesystem::path cache_path_;

    nlohmann::json config_;
    user_records_t records_;
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

    log_redirect_t redirect{};
	try
	{
        std::clog << "redirected log" << std::endl;
        make_process_protected();
        std::clog << "made process protected" << std::endl;

		// Perform application initialization:
		ATOM atom = RegisterCustomWindow(hInstance);
		HWND hWnd = InitInstance(hInstance, atom);
		handle_win32_result(::WTSRegisterSessionNotification(hWnd, NOTIFY_FOR_ALL_SESSIONS), __FILE__, __LINE__);

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
					tracker.session_suspend(static_cast<DWORD>(msg.lParam));
					break;

				case WTS_SESSION_UNLOCK:
                case WTS_SESSION_LOGON:
                case WTS_REMOTE_CONNECT:
					tracker.session_resume(static_cast<DWORD>(msg.lParam));
					break;
				}
			}
            break;
			}
        }

        handle_win32_result(::WTSUnRegisterSessionNotification(hWnd), __FILE__, __LINE__);

    }
    catch (std::exception const& ex)
    {
        std::clog << "exception: " << ex.what() << std::endl;
        return -1;
    }

    return 0;
}

HWND InitInstance(HINSTANCE hInstance, ATOM atom)
{
   hInst = hInstance;
   HWND hWnd = CreateWindowW(window_class_name, nullptr, WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);
   if (hWnd == nullptr)
       throw_last_win32_error(__FILE__, __LINE__);

   ::ShowWindow(hWnd, SW_HIDE);
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

u8string app_path()
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
        throw_last_win32_error(__FILE__, __LINE__);
    }
    acl_ptr acl{ p_acl };

    handle_ptr process{ ::GetCurrentProcess() };
    if (::SetSecurityInfo(process.get(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, acl.get(), nullptr) != ERROR_SUCCESS)
    {
        throw_last_win32_error(__FILE__, __LINE__);
    }
}

log_redirect_t::log_redirect_t()
    : original_(std::clog.rdbuf())
{
    filesystem::path path = app_path() + u8string{ u8"\\log.txt" };
    if (filesystem::exists(path))
        logfile_.open(path, std::ios::out | std::ios::in);
    else
        logfile_.open(path, std::ios::out);
    
    if (logfile_.is_open())
        std::clog.rdbuf(logfile_.rdbuf());
    else
        original_ = nullptr;

    std::clog << "================================================================================" << std::endl;
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
    , config_path_(app_path() + u8string{ u8"\\config.json" })
    , cache_path_(app_path() + u8string{ u8"\\cache.json" })
{
    config_ = read_json(config_path_);
    records_ = read_cache(read_json(cache_path_), config_);
    update_logged_in_users();
}


void time_tracker_t::update_timer(UINT_PTR timer_id)
{
    if (timer_id_ != 0u)
    {
        ::KillTimer(hwnd_, timer_id_);
    }
    if (timer_id_ == 0u)
    {
        timer_id_ = static_cast<DWORD>(timer_id);
    }

    bool any_logged_in = std::any_of(begin(records_), end(records_), [](auto& pair) { return pair.second.logged_in; });
    if (!any_logged_in)
    {
        timer_id_ = 0u;
        return;
    }

    // Handle append ellapsed time and timer update.
    auto next = append_ellapsed_time();
    chrono::milliseconds timer_amount = chrono::duration_cast<chrono::milliseconds>(next);
    UINT_PTR result = ::SetTimer(hwnd_, timer_id_, static_cast<UINT>(timer_amount.count()), nullptr);
    if (result == FALSE)
    {
        throw_last_win32_error(__FILE__, __LINE__);
    }
}

void time_tracker_t::session_suspend(DWORD sessionId)
{
    append_ellapsed_time();
    auto user = get_user(sessionId);
    std::clog << "Session suspended for " << user.name << " (" << chrono::system_clock::now() << ")" << std::endl;

    auto itr = records_.find(user.name);
    if (itr == end(records_))
        return; // User is not a user we care about.

    itr->second.user.session_id = sessionId;
    itr->second.logged_in = false;

    cache_user_records();
}

void time_tracker_t::session_resume(DWORD sessionId)
{
    auto user = get_user(sessionId);
    std::clog << "Session resumed for " << user.name << " (" << chrono::system_clock::now() << ")" << std::endl;

    auto itr = records_.find(user.name);
    if (itr == end(records_))
        return; // User is not a user we care about.

    itr->second.user.session_id = sessionId;
    itr->second.logged_in = true;

    update_timer(timer_id_);
}

user_t time_tracker_t::get_user(DWORD sessionId) const
{
    LPSTR buffer = nullptr;
    DWORD bytes = 0u;
    BOOL result = ::WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, sessionId, WTS_INFO_CLASS::WTSUserName, &buffer, &bytes);
    if (result == FALSE)
    {
        // Couldn't get session directly... search in records.
        auto itr = std::find_if(begin(records_), end(records_), [&](auto const& pair)
            {
                return pair.second.user.session_id == sessionId;
            });
        if (itr == end(records_))
        {
            std::clog << "Failed to find any user for session id " << sessionId << std::endl;
            return user_t{};
        }

        return itr->second.user;
    }

    user_t user;
    if (buffer != nullptr && bytes > 0u)
    {
        user.name = buffer;
    }

    user.session_id = sessionId;
    return user;
}

chrono::seconds time_tracker_t::append_ellapsed_time()
{
    using namespace std;
    using namespace std::chrono;

    auto const now = chrono::system_clock::now();
    auto const ellapsed = now - t0_;
    t0_ = now;
    string const todays_date = today(now);

    seconds min_remainder = seconds{ 60u * 60u };
	for (auto& pair : records_)
	{
		if (!pair.second.logged_in)
			continue; // Skip logged out users.

		pair.second.accumulated += duration_cast<seconds>(ellapsed);
		if (pair.second.date != todays_date)
		{
			pair.second.accumulated = seconds{ 0 };
			pair.second.date = todays_date;
		}
		if (pair.second.accumulated >= pair.second.allowed)
		{
			force_logout(pair.second.user);
			continue;
		}

		seconds const remainder = pair.second.allowed - pair.second.accumulated;
		min_remainder = min(min_remainder, remainder);
		if (remainder <= warn_before_logout)
		{
			send_logout_warning(pair.second.user, remainder);
		}
	}

	return min_remainder;
}

void time_tracker_t::send_logout_warning(user_t const &user, std::chrono::seconds remaining)
{
	string msg = format("User {} has used up screen time for today and will be logged out in {}", user.name, remaining);
    send_msg(user, msg);
}

void time_tracker_t::send_msg(user_t const &user, std::string const &msg)
{
    std::stringstream ss;
    ss << "msg " << user.session_id << " \"" << msg << '"';
    std::string cmd = ss.str();
    int result = std::system(cmd.c_str());
    if (result != 0)
        std::clog << "sending msg '" << msg << "' to " << user.name << ":" << user.session_id << " failed (" << result << ")" << std::endl;
    else
        std::clog << "sent msg '" << msg << "' to " << user.name << std::endl;
}

void time_tracker_t::force_logout(user_t const &user)
{
    auto now = chrono::system_clock::now();
    std::clog << "Logging off user " << user.name << " (" << now << ")" << std::endl;
    BOOL result = ::WTSLogoffSession(WTS_CURRENT_SERVER_HANDLE, user.session_id, FALSE);
    if (result == FALSE)
    {
        error_code ec{ static_cast<int>(::GetLastError()), system_category() };
        system_error error{ ec };
        std::clog << "WTSLogoffSession() failed: (" << ec << ") " << error.what() << std::endl;

        std::stringstream ss;
        ss << user.name << " has exceeded allotted time. Log out!";
        send_msg(user, ss.str());
    }
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

nlohmann::json time_tracker_t::read_json(filesystem::path const &file)
{
    nlohmann::json json;
    ifstream file_stream{ file };
    if (file_stream.is_open())
    {
        file_stream >> json;
        std::clog << "Read json from: " << file << std::endl;
    }
    else
    {
        std::clog << "Did not open json file for reading: " << file << std::endl;
    }
    return json;
}

time_tracker_t::user_records_t time_tracker_t::read_cache(nlohmann::json const& json, nlohmann::json const &config)
{
    using namespace std;
    using namespace std::chrono;
    user_records_t records;

    for (auto &entry : json)
    {
        user_record_t record;
        record.user.name = entry["user"];
        record.accumulated = seconds{ static_cast<size_t>(entry["accumulated"]) };
        record.date = entry["date"];

        unsigned int allowed_min = config[record.user.name];
        record.allowed = duration_cast<seconds>(minutes{ allowed_min });
        records.insert(make_pair(string{ record.user.name }, move(record)));
    }

    for (auto &item : config.items())
    {
        auto itr = records.find(item.key());
        if (itr == end(records))
        {
            user_record_t record;
            record.user.name = item.key();
            unsigned int allowed_min = item.value();
            record.allowed = duration_cast<seconds>(minutes{ allowed_min });
            records.insert(make_pair(string{ record.user.name }, move(record)));
        }
    }

    return records;
}

void time_tracker_t::cache_user_records() const
{
    nlohmann::json json;
    for (auto const& pair : records_)
    {
        nlohmann::json record;
        record["user"] = pair.second.user.name;
        record["accumulated"] = pair.second.accumulated.count();
        record["date"] = pair.second.date;
        json.push_back(record);
    }

    write_json(cache_path_, json);
}

void time_tracker_t::update_logged_in_users()
{
    PWTS_SESSION_INFOA sessions = nullptr;
    DWORD session_count = 0u;
    BOOL result = ::WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0u, 1u, &sessions, &session_count);
    if (result == FALSE || sessions == nullptr || session_count == 0)
    {
        std::clog << "Failed to update logged in users!" << std::endl;
        return;
    }

    for (auto session = sessions; session != sessions + session_count; ++session)
    {
        if (session->State != WTSActive)
            continue;

        LPSTR buffer = nullptr;
        DWORD bytes = 0u;
        BOOL result = ::WTSQuerySessionInformationA(WTS_CURRENT_SERVER_HANDLE, session->SessionId, WTS_INFO_CLASS::WTSUserName, &buffer, &bytes);
        if (result == FALSE || buffer == nullptr || bytes == 0)
            continue;

        std::string name = buffer;
        auto itr = records_.find(name);
        if (itr == end(records_))
            continue;

        itr->second.logged_in = true;
    }
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


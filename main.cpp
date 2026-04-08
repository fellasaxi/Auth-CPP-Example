#include <Windows.h>
#include <string>

#include "auth.hpp"
#include "skStr.h"
#include "lazy.h"
#include "protection.h"
std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace AxiAuth;

std::string name = skCrypt("name").decrypt(); 
std::string ownerid = skCrypt("ownerid").decrypt(); 
std::string secret = skCrypt("yoursecret").decrypt(); 
std::string version = skCrypt("1.0").decrypt(); 
std::string url = skCrypt("https://auth.axiverse.site/api/1.2/").decrypt(); 
std::string path = skCrypt("").decrypt();

api AuthApp(name, ownerid, secret, version, url, path);

int main()
{
	std::thread(Protection_Loop).detach();
	LI_FN(SetConsoleTitleA).get()(skCrypt("Loader"));
	LI_FN(printf).get()(skCrypt("\n\n Connecting.."));
	AuthApp.init();
	if (!AuthApp.response.success)
	{
		LI_FN(printf).get()(skCrypt("\n Status: %s"), AuthApp.response.message.c_str());
		LI_FN(Sleep).get()(1500);
		LI_FN(abort).get()();
	}
	LI_FN(printf).get()(skCrypt("\n Checking session validation status (remove this if causing your loader to be slow)"));
	AuthApp.check();
	LI_FN(printf).get()(skCrypt("\n\n [1] Login\n [2] Register\n [3] Upgrade\n [4] License key only\n\n Choose option: "));
	
	int option;
	std::string username;
	std::string password;
	std::string key;
	
	std::cin >> option;
	switch (option)
	{
	case 1:
		LI_FN(printf).get()(skCrypt("\n\n Enter username: "));
		std::cin >> username;
		LI_FN(printf).get()(skCrypt("\n Enter password: "));
		std::cin >> password;
		AuthApp.login(username, password);
		break;
	case 2:
		LI_FN(printf).get()(skCrypt("\n\n Enter username: "));
		std::cin >> username;
		LI_FN(printf).get()(skCrypt("\n Enter password: "));
		std::cin >> password;
		LI_FN(printf).get()(skCrypt("\n Enter license: "));
		std::cin >> key;
		AuthApp.regstr(username, password, key);
		break;
	case 3:
		LI_FN(printf).get()(skCrypt("\n\n Enter username: "));
		std::cin >> username;
		LI_FN(printf).get()(skCrypt("\n Enter license: "));
		std::cin >> key;
		AuthApp.upgrade(username, key);
		break;
	case 4:
		LI_FN(printf).get()(skCrypt("\n Enter license: "));
		std::cin >> key;
		AuthApp.license(key);
		break;
	default:
		LI_FN(printf).get()(skCrypt("\n\n Status: Failure: Invalid Selection"));
		LI_FN(Sleep).get()(3000);
		LI_FN(abort).get()();
	}
	
	if (!AuthApp.response.success)
	{
		LI_FN(printf).get()(skCrypt("\n Status: %s"), AuthApp.response.message.c_str());
		LI_FN(Sleep).get()(1500);
		LI_FN(abort).get()();
	}
	
	LI_FN(printf).get()(skCrypt("\n User data:"));
	LI_FN(printf).get()(skCrypt("\n Username: %s"), AuthApp.user_data.username.c_str());
	LI_FN(printf).get()(skCrypt("\n IP address: %s"), AuthApp.user_data.ip.c_str());
	LI_FN(printf).get()(skCrypt("\n Hardware-Id: %s"), AuthApp.user_data.hwid.c_str());
	LI_FN(printf).get()(skCrypt("\n Create date: %s"), tm_to_readable_time(timet_to_tm(string_to_timet(AuthApp.user_data.createdate.c_str()))).c_str());
	LI_FN(printf).get()(skCrypt("\n Last login: %s"), tm_to_readable_time(timet_to_tm(string_to_timet(AuthApp.user_data.lastlogin.c_str()))).c_str());
	LI_FN(printf).get()(skCrypt("\n Subscription name(s): "));
	std::string subs;
	for (auto& sub : AuthApp.user_data.subscriptions)
		subs += sub.name + " ";
	LI_FN(printf).get()(subs.c_str());
	LI_FN(printf).get()(skCrypt("\n Subscription expiry: %s"), tm_to_readable_time(timet_to_tm(string_to_timet(AuthApp.user_data.subscriptions[0].expiry.c_str()))).c_str());
	AuthApp.check();
	LI_FN(printf).get()(skCrypt("\n Current Session Validation Status: %s"), AuthApp.response.message.c_str());

	LI_FN(printf).get()(skCrypt("\n\n Closing in ten seconds..."));
	LI_FN(Sleep).get()(10000);
	LI_FN(abort).get()();
}

std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	LI_FN(strftime).get()(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = LI_FN(strtol).get()(timestamp.c_str(), NULL, 10); 

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}

#include <iostream>
#include <cstring>
using namespace std;

void strip_newline(char* buf, int64_t length){
    char* i;
    for(i = &buf[length]; i >= buf; i--){
        if ( *i == '\n' )
            *i = '\0';
    }
}

class User{
private:
    char username[0x50]{};
    char password[0x50]{};
public:
    User(){}
    User(const char* username, const char* password){
        strncpy(this->username, username, 0x50);
        strncpy(this->password, password, 0x50);
    }
    void read_name(){
        char name[80];
        fgets(name, 79, stdin);
        strip_newline(name, 80);
        strncpy(this->username, name, 0x50);
    }
    void read_password(){
        char pwd[80];
        fgets(pwd, 79, stdin);
        strip_newline(pwd, 80);
        strncpy(this->password, pwd, 0x50);
    }
public:
    virtual char* get_password(){
        return this->password;
    }
    virtual void shell(){
        puts("No shell for you!");
    }
};

class Admin : User{
public:
    Admin(const char* username, const char* password) : User(username, password){}
    void shell() override{
        puts("Congratulations!");
        system("/bin/sh");
    }
    char* get_password() override{
        return User::get_password();
    }
};

typedef struct checker{
    void (*check)();
    int64_t null[2];
}checker;

checker* password_checker(void (*check)()){
    checker checker;
    checker.check = check;
    return &checker;
}

User login;

int main() {
    char admin_password[88];
    cout << "Hello, World!" << endl;
    setbuf(stdout, 0);
    strcpy(admin_password, "2jctf_pa5sw0rd");
    memset(&admin_password[15], 0, 65);
    Admin admin((const char*)"admin", admin_password);
    puts(
            " _____   _  ____ _____ _____   _                _       \n"
            "|__  /  | |/ ___|_   _|  ___| | |    ___   __ _(_)_ __  \n"
            "  / /_  | | |     | | | |_    | |   / _ \\ / _` | | '_ \\ \n"
            " / /| |_| | |___  | | |  _|   | |__| (_) | (_| | | | | |\n"
            "/____\\___/ \\____| |_| |_|     |_____\\___/ \\__, |_|_| |_|\n"
            "                                          |___/         ");
    printf("Please enter username: ");
    login.read_name();
    printf("Please enter password: ");
    auto greeting_func = []()->void{
        puts("<===Welcome to ZJCTF!!!===>");
        return login.shell();
    };
    checker* exec = password_checker(greeting_func);
    login.read_password();
    char* admin_pwd = admin.get_password();
    char* user_pwd = login.get_password();
    [](checker* exec, char* admin_pwd, char* user_pwd)->void{
        char s[88];
        if(!strcmp(admin_pwd, user_pwd)){
            snprintf(s, 0x50uLL, "Password accepted: %s\n", s);
            puts(s);
            exec->check();
        }else{
            puts("Nope!");
        }
    }(exec, admin_pwd, user_pwd);
    return 0;
}

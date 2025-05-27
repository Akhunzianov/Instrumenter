#include "Reader.hpp"

void Reader::execute() {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("execute: pipe failed\n");
        _exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("execute: pipe failed\n");
        _exit(1);
    }

    if (pid == 0) {
        close(pipefd[0]);          
        if (dup2(pipefd[1], 3) < 0) {
            perror("execute: dup2 failed\n");
            _exit(1);
        }
        close(pipefd[1]);

        const char* path = executable_path.c_str();
        char *argv[] = {
            const_cast<char*>(path),
            const_cast<char*>("-l"),
            const_cast<char*>("-a"),
            nullptr
        };
        execv(path, argv);
        perror("execute: execv failed\n");
        _exit(1);
    }

    close(pipefd[1]);               

    int flags = fcntl(pipefd[0], F_GETFL, 0);
    fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);

    std::vector<char> buffer(4096);
    while (true) {
        ssize_t n = read(pipefd[0], buffer.data(), buffer.size());
        if (n > 0) {
            std::cout.write(buffer.data(), n);
            std::cout.flush();
        }

        int status = 0;
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) {
            if (WIFEXITED(status)) {
                std::cerr << "\nChild exited with code " << WEXITSTATUS(status) << "\n";
            } 
            else if (WIFSIGNALED(status)) {
                std::cerr << "\nChild killed by signal " << WTERMSIG(status) << "\n";
            }
            break;
        }

        if (n < 0 && errno != EAGAIN) {
            perror("execute: read error\n");
            break;
        }

        // не слишком жадим по CPU
        // usleep(100'000);
    }

    close(pipefd[0]);
}
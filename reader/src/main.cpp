#include "Reader.hpp"

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: ./program <path-to-in-binary> <path-to-out-binary>\n";
        return 1;
    }

    std::string path = argv[1];
    std::string out_path = argv[2];

    std::unique_ptr<Parser> parser = createParser(path);
    parser->load(path, out_path);

    auto inst_ptr = std::make_unique<Instrument>(std::move(parser));

    Reader reader(std::move(inst_ptr));
    reader.execute();
}
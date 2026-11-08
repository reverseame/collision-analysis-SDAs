// sdhash-pairs: sdhash 3.4 score of digest pairs, without the Cartesian product of `sdhash -c`.
//
// Input (stdin): one line per pair, "<sdbf A>\t<sdbf B>", each in full format
// "sdbf:03:<name length>:<name>:<size>:sha1:...".
// Output (stdout): one line per pair with the value of sdbf::compare (0-100; -1 if not comparable).
#include "sdbf/sdbf_class.h"
#include "sdbf/sdbf_defines.h"

#include <iostream>
#include <string>

int main() {
    std::ios::sync_with_stdio(false);
    sdbf::config = new sdbf_conf(1, 0, _MAX_ELEM_COUNT, _MAX_ELEM_COUNT_DD);
    std::string line;
    while (std::getline(std::cin, line)) {
        const size_t tab = line.find('\t');
        if (tab == std::string::npos) {
            std::cout << "error\n";
            continue;
        }
        sdbf a(line.substr(0, tab));
        sdbf b(line.substr(tab + 1));
        std::cout << a.compare(&b, 0) << '\n';
    }
    return 0;
}

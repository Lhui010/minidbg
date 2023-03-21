#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <vector>
#include <iomanip>

#include "linenoise.h"
#include "debugger.hpp"
#include "registers.hpp"

using namespace minidbg;

std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> out {};
    std::stringstream ss {s};
    std::string item;

    while (std::getline(ss, item, delimiter)) {
        out.push_back(item);
    }

    return out;
}

bool is_prefix(const std::string &s, const std::string &of) {
    if (s.size() > of.size())
        return false;
    return std::equal(s.begin(), s.end(), of.begin());
}

bool is_suffix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
}

symbol_type to_symbol_type(elf::stt sym) {
    switch (sym) {
    case elf::stt::notype: return symbol_type::notype;
    case elf::stt::object: return symbol_type::object;
    case elf::stt::func: return symbol_type::func;
    case elf::stt::section: return symbol_type::section;
    case elf::stt::file: return symbol_type::file;
    default: return symbol_type::notype;
    }
}

void debugger::remove_breakpoint(std::intptr_t addr) {
    if (m_breakpoints.at(addr).is_enabled()) {
        m_breakpoints.at(addr).disable();
    }
    m_breakpoints.erase(addr);
}

void debugger::step_out() {
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);

    bool should_remove_breakpoint = false;

    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if (should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void debugger::set_breakpoint_at_function(const std::string &name) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && dwarf::at_name(die) == name) {
                auto low_pc = dwarf::at_low_pc(die);
                auto entry = get_line_entry_from_pc(low_pc);
                ++entry;
                set_breakpoint_at_address(offset_dwarf_address(entry->address));
            }
        }
    }
}

void debugger::set_breakpoint_at_line(const std::string &file, unsigned int line) {
    for (const auto& cu : m_dwarf.compilation_units()) {
        if (is_suffix(file, dwarf::at_name(cu.root()))) {
            const auto& lt = cu.get_line_table();

            for (const auto& entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                }
            }
        }
    }
}

std::vector<symbol> debugger::lookup_symbol(const std::string& name) {
    std::vector<symbol> syms;

    for (auto &sec : m_elf.sections()) {
        if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym)
            continue;

        for (auto sym : sec.as_symtab()) {
            if (sym.get_name() == name) {
                auto &d = sym.get_data();
                syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
            }
        }
    }

    return syms;
}

void debugger::print_backtrace() {
    auto output_frame = [this, frame_number = 0] (auto&& func) mutable {
        std::cout << "frame #" << frame_number++ << ": 0x" << offset_dwarf_address(dwarf::at_low_pc(func))
                  << ' ' << dwarf::at_name(func) << std::endl;
    };

    auto current_func = get_function_from_pc(get_offset_pc());
    output_frame(current_func);

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer+8);

    while (dwarf::at_name(current_func) != "main") {
        current_func = get_function_from_pc(return_address);
        output_frame(current_func);
        frame_pointer = read_memory(frame_pointer);
        return_address = read_memory(frame_pointer+8);
    }
}

uint64_t debugger::get_offset_pc() {
    return offset_load_address(get_pc());
}

void debugger::step_in() {
    auto line = get_line_entry_from_pc(get_offset_pc()) -> line;
    while (get_line_entry_from_pc(get_offset_pc()) -> line == line) {
        single_step_instruction_with_breakpoint_check();
    }

    auto line_entry = get_line_entry_from_pc(get_offset_pc());
    print_source(line_entry->file->path, line_entry->line);
}

void debugger::step_over() {
    auto func = get_function_from_pc(get_offset_pc());
    auto func_entry = dwarf::at_low_pc(func);
    auto func_end = dwarf::at_high_pc(func);

    auto line = get_line_entry_from_pc(func_entry);
    auto start_line = get_line_entry_from_pc(get_offset_pc());

    std::vector<std::intptr_t> to_delete {};

    while (line->address < func_end) {
        auto load_address = offset_dwarf_address(line->address);
        if (line->address != start_line->address && !m_breakpoints.count(load_address)) {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line;
    }

    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }

    continue_execution();

    for (auto addr : to_delete) {
        remove_breakpoint(addr);
    }

}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(pc)) {
            for (const auto &die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (dwarf::die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }

    throw std::out_of_range("Cannot find function");
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (dwarf::die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range("Cannot find line entry");
            } else {
                return it;
            }
        }
    }

    throw std::out_of_range("Cannot find line entry");
}

void debugger::initialise_load_address() {
    if (m_elf.get_hdr().type == elf::et::dyn) {
        std::ifstream map("/proc" + std::to_string(m_pid) + "/maps");

        std::string addr;
        std::getline(map, addr, '-');

        m_load_address = std::stoi(addr, 0, 16);
    }
}

uint64_t debugger::offset_load_address(uint64_t addr) {
    return addr - m_load_address;
}

uint64_t debugger::offset_dwarf_address(uint64_t addr) {
    return addr + m_load_address;
}

void debugger::print_source(const std::string &file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};

    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context -line : 0) + 1;

    char c{};
    auto current_line = 1u;
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }
    std::cout << (current_line == line ? "> " : " ");

    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            std::cout << (current_line == line ? "> " : " ");
        }
    }
    std::cout << std::endl;
}

void debugger::dump_register() {
    for (const auto& rd: g_register_descriptors) {
        std::cout << rd.name << " 0x"
                  << std::setfill('0') << std::setw(16) <<std::hex
                  << get_register_value(m_pid, rd.r)
                  << std::endl;
    }
}

uint64_t debugger::read_memory(uint64_t address) {
    return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
    ptrace(PTRACE_POKEDATA, m_pid,address, value);
}

uint64_t debugger::get_pc() {
    return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
    set_register_value(m_pid, reg::rip, pc);
}

void debugger::step_over_breakpoint() {
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];

        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        } 
    }
}

void debugger::single_step_instruction() {
    ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
    if (m_breakpoints.count(get_pc())) {
        step_over_breakpoint();
    } else {
        single_step_instruction();
    }
}

siginfo_t debugger::get_signal_info() {
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
    return info;
}

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
        case SI_KERNEL:
        case TRAP_BRKPT:
        {
            set_pc(get_pc() - 1);
            std::cout << "Hit breakpoin at address 0x" << std::hex << get_pc() << std::endl;
            auto offset_pc = offset_load_address(get_pc());
            auto line_entry = get_line_entry_from_pc(offset_pc);
            print_source(line_entry->file->path, line_entry->line);
            return;
        }
        case TRAP_TRACE:
            return;
        default:
            std::cout << "Unknown SIGTRAP code" << info.si_code << std::endl;
            return;
    }
}

void debugger::wait_for_signal() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);

    auto siginfo = get_signal_info();
    switch (siginfo.si_signo) {
        case SIGTRAP:
            handle_sigtrap(siginfo);
            break;
        case SIGSEGV:
            std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
            break;
        default:
            std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
    std::cerr<< "Set breakpoint at address 0x" << std::hex << addr << std::endl;
    breakpoint bp {m_pid, addr};
    bp.enable();
    m_breakpoints[addr] = bp;
}

void execute_debugee (const std::string &prog_name) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(prog_name.c_str(), prog_name.c_str(), nullptr);
}

void debugger::continue_execution() {
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
    wait_for_signal();
}

void debugger::handle_command(const std::string &line) {
    auto args = split(line, ' ');
    if (args.empty()) {
        //nothing to do!
        return;
    }
    auto command = args[0];
    if (is_prefix(command, "continue")) {
        continue_execution();
    } else if (is_prefix(command, "break")) {
        if (args.size() == 1) {
            std::cerr << "No address\n";
            return;
        }
        if (args[1][0] == '0' && args[1][1] == 'x') {
            //todo: check wether the address is valid.
            std::string addr {args[1], 2};
            set_breakpoint_at_address(std::stol(addr, 0, 16));
        } else if (args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_line(file_and_line[0], std::stoi(file_and_line[1]));
        } else {
            set_breakpoint_at_function(args[1]);
        }
    } else if (is_prefix(command, "symbol")) {
        auto syms = lookup_symbol(args[1]);
        for (auto&& s : syms) {
            std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
        }
    } else if (is_prefix(command, "backtrace")) {
        print_backtrace();
    } else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_register();
        } else if (is_prefix(args[1], "read")) {
            std::cout << get_register_value(m_pid, get_register_from_name(args[2]))
                      << std::endl;
        } else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
        }
    } else if (is_prefix(command, "memory")) {
        std::string addr {args[2], 2};
        if (is_prefix(args[1], "read")) {
            std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
        } else if (is_prefix(args[1], "write")) {
            std::string val {args[3], 2};
            write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
        }   
    } else if (is_prefix(command, "step")) {
        step_in();
    } else if (is_prefix(command, "next")) {
        step_over();
    } else if (is_prefix(command, "finish")) {
        step_out();
    } else if (is_prefix(command, "stepi")) {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_pc(get_pc());
        print_source(line_entry->file->path, line_entry->line);
    } else {
        std::cerr << "Unknown command\n";
    }
}

void debugger::run() {
    wait_for_signal();
    initialise_load_address();

    char* line = nullptr;
    while ((line = linenoise("minidbg> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }

    auto prog = argv[1];

    auto pid = fork();
    if (pid == 0) {
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(prog);       
    } 
    else if (pid >= 1) {
        std::cout<< "Started debugging process: " << pid << '\n';
        debugger dbg{prog, pid};
        dbg.run();
    }
}
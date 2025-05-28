# Sandbox - Secure Process Execution with Landlock and Seccomp

A lightweight sandboxing tool that uses Linux's Landlock LSM and seccomp-bpf to provide filesystem access control and syscall filtering for untrusted processes.

## Features

- **Filesystem Access Control**: Fine-grained control over read, write, and execute permissions using Landlock
- **Syscall Filtering**: Blocks dangerous system calls using seccomp-bpf
- **Unprivileged Operation**: Works without root privileges
- **Inheritance**: Restrictions are inherited by child processes
- **Logging**: Optional logging of sandbox events

## Requirements

- Linux kernel 5.13+ (for Landlock support)
- GCC with C99 support
- Python 3 (for tests)

## Building

make


## Usage

./sandbox [OPTIONS] executable [args...]


### Options

- `--read=PATH`: Allow read access to PATH and its subdirectories
- `--write=PATH`: Allow read/write access to PATH and its subdirectories
- `--exec=PATH`: Allow execution of files from PATH and its subdirectories
- `--logfile=PATH`: Log sandbox events to specified file

### Examples

**Basic Python script execution:**

/sandbox --read=/usr/lib --read=/etc --exec=/usr/bin --write=/tmp python3 script.py



## How It Works

The sandbox combines two Linux security mechanisms:

1. **Landlock LSM**: Provides filesystem access control by restricting which directories a process can access for reading, writing, or executing files.

2. **Seccomp-BPF**: Filters system calls, allowing only essential syscalls needed for basic program operation while blocking potentially dangerous ones.

### Security Model

- Processes start with **no filesystem access** by default
- Access must be explicitly granted via command-line options
- Restrictions cannot be removed once applied
- Child processes inherit all restrictions
- Dangerous syscalls are blocked at the kernel level

## Testing

Run the test suite:


## Installation

make install


This installs the `sandbox` binary to `/usr/local/bin/`.

## Limitations

- Requires Linux kernel 5.13+ for Landlock support
- Some applications may require additional syscalls to be whitelisted
- Network access is not currently restricted (future enhancement)
- No support for user namespace isolation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security Notice

This tool provides defense-in-depth security but should not be considered a complete security solution. Always follow security best practices and consider additional isolation mechanisms for highly sensitive applications.



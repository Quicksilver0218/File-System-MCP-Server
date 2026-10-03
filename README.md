# File-System-MCP-Server
A fork of https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem

## Usage
```json
{
  "mcpServers": {
    "File System": {
      "command": "npx",
      "args": [
        "--allow-git",
        "all",
        "-y",
        "github:Quicksilver0218/File-System-MCP-Server",
        "${env:VSCODE_CWD}", // or "+%VSCODE_CWD%"
        "*${env:VSCODE_CWD}/.git"
      ]
    }
  }
}
```

### Access Control
Paths with a prefix can be added to the arguments to limit access to specific directories.
- `+<path>` or `<path>`: Add path to access list
- `*<path>`: Add path to read-only access list
- `-<path>`: Remove path from access list

When conflicts occur, the strictest rule is applied.

## Tools
17 tools are available:

### Read
- read_text_file
- read_media_file
- read_multiple_files
- find_text_in_file

### Write
- edit_text_file
- write_file
- remove_files
- create_directory
- move_file
- copy_file

### List
- list_directory
- list_directory_with_sizes
- directory_tree
- search_files
- get_file_info
- list_allowed_paths

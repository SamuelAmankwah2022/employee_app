import os

def search_files_for_string(directory, target_string, file_extensions=(".html", ".py", ".js")):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(file_extensions):
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        for i, line in enumerate(f, start=1):
                            if target_string in line:
                                print(f"{path} - Line {i}: {line.strip()}")
                except Exception as e:
                    print(f"Could not read {path}: {e}")

# Set the directory and string to search for
project_directory = "."  # Current folder
string_to_find = "/employee/login"  # You can change this to anything else

search_files_for_string(project_directory, string_to_find)
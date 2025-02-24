def read_jwt_from_file(file_path: str) -> str:
    with open(file_path, 'r') as file:
        return file.read().strip()
    
jwt = read_jwt_from_file('Assignment_1\q2\jwt.txt')


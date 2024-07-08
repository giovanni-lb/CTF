from collections import deque
from hashlib import sha256

def create_grid():
    with open('maze_dump.bin', 'rb') as f:
        maze_data = f.read()

    maze_text = ''.join(['#' if b == 0x23 else ' ' for b in maze_data])
    grid = [list(maze_text[i:i + 64]) for i in range(0, len(maze_text), 64)]
    return grid


def print_grid(grid):
    for row in grid:
        print("".join(row))


def is_valid_move(grid, x, y):
    return 0 <= x < 63 and 0 <= y < 63 and grid[y][x] != "#"


def bfs(grid, start, end):
    queue = deque([(start, "")])
    visited = set([start])

    while queue:
        (x, y), path = queue.popleft()

        if (x, y) == end:
            return path

        for dx, dy, command in [(-1, 0, "L"), (1, 0, "R"), (0, -1, "U"), (0, 1, "D")]:
            new_x, new_y = x + dx, y + dy

            if is_valid_move(grid, new_x, new_y) and (new_x, new_y) not in visited:
                queue.append(((new_x, new_y), path + command))
                visited.add((new_x, new_y))

    return None


def draw_path_on_grid(grid, path, start):
    x, y = start
    for command in path:
        if command == "L":
            x -= 1
        elif command == "R":
            x += 1
        elif command == "U":
            y -= 1
        elif command == "D":
            y += 1
        grid[y][x] = '.'

def main():
    grid = create_grid()
    #print_grid(grid)
    start, end = (0, 0), (62, 62)
    path = bfs(grid, start, end)

    if path:
        print(f"Found a path: {path}")
        draw_path_on_grid(grid, path, start)
        print("Completed maze with path:")
        print_grid(grid)
        flag = "FCSC{" + sha256(path.encode()).hexdigest() + "}"
        print(f"Flag: {flag}")
    else:
        print("No path found")

if __name__ == "__main__":
    main()

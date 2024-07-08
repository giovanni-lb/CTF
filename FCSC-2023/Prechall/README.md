# Teaser FCSC2023 🔥
###### stegano, lsb, reverse, maze

> Il y a un prechall 🦕 à trouver sur le site en attendant l'ouverture officielle.

#### TL;DR
* find /endpoint in source code
* Puzzle & LSB1
* Puzzle & LSB2
* Maze solve

#### Challenge Discovery
On the main page of the CTFd we can see some comment in the HTML source code that give us an endpoint with the Teaser challenge for FCSC2023:
```
 En attendant l'ouverture, un flag est à trouver sur ce site. Voir sur /teasing 🔥
```
We've got a scrumble puzzle image with an hint (speaking about LSB), so first of all we need to reassemble the puzzle in order to get the hidden data in lsb 
#### Stegano part

The puzzle is divide into multiple image (5 x 11 images), so first of all we need to get all image part in order to replace them to get the original image, to do so I create a python3 script to get all images:
```python
from PIL import Image

image = Image.open("step2.png")
image_width, image_height = image.size
grid_x, grid_y = 5, 11

width = image_width 
height = image_height 

for i in range(grid_y):
    for j in range(grid_x):
        left = j * width
        upper = i * height
        right = (j + 1) * width
        lower = (i + 1) * height
        
        # get the image at position i,j
        portion = image.crop((left, upper, right, lower))
        
        # Save img
        portion_name = f"step2/portion_{i}_{j}.png"
        portion.save(portion_name)
```
that will save all image part into a directory.

Then when we got the original image we can extract hidden data in the LSB **L** east **S** ignificant **B** it  (R,G,B channel 0), that will give us an other puzzle with hidden data in the LSB. So we repeat the process and then got an ELF.
I used Cyberchef (https://gchq.github.io/CyberChef/#recipe=Extract_LSB('R','G','B','','Row',0)) to extract LSB

#### Reverse part
The reverse part is straightforward because they is only 1 function, that will create a 64x64 mazze (using ' ' for clear path and '#' for wall):
```c
  for (i = 0; i < 0x3f; i2 = i + 1) {
    for (j = 0; j < 0x40; j2 = j + 1) {
      if (&DAT_00104060 + i) >> (j & 0x3f) & 1) == 0) {
        (local_1028 + j + i * 0x40) = 0x20; // 0x20 = ' '
      }
      else {
        (local_1028 + j + i * 0x40) = 0x23; // 0x23 = '#'
      }
    }
  }
  
```

So we dump the maze using GDB:
Maze location : 0x7fffffffceef-0x7fffffffdeaf 

gdb:
```
b *0x555555554000 + 0x138a #break before cmp x,y,z to get the full maze
dump binary memory maze_dump.bin 0x7fffffffceef 0x7fffffffdeaf #dump the maze into a file
```

And then we create a python3 script in order to solve this maze using BFS method to be more efficient.
#### Final Script

```python
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
```

```
$ python3 solve.py
Found a path: RDDDDDDDDDRRDDDDDDRRDDRRRRDDRRRRRRRRDDLLDDRRDDDDDDLLDDDDRRRRRRUURRRRRRRRUUUURRDDRRRRRRRRRRRRDDDDDDRRUUUURRDDRRUUUURRRRUURRDDRRDDRRRRDDDDLLDDDDDDDDDDRRDDLLLLDDDDLLLLDDRRRRDDRRRRDDLLDDDDRRRD
Completed maze with path:
 .############################################################# 
#.  # # #   #   #   # #           #   #     # #   #           # 
#.### # # ##### ### # ### # ### # # # # # ### ### # # ### ##### 
#.  # #   #         # # # # #   #   # # # #   #   # # # # #   # 
#.### ### # ####### # # # # ### # ### ### ### # # ### # ##### # 
#.#   #     # # # #   #   #   # #   #       #   # #     #     # 
#.# ####### # # # ### ##### ### ##### ######### ### ##### ### # 
#.              # #   #   #   # #     #     #   # #   #   # # # 
#.####### ####### # # ### ### ########### ##### # # ##### # ### 
#...#       #     # #   #   #   # #           #     # #   #   # 
###.######### ##### ##### ### ### # ####### ### ### # # ### ### 
#  .#         #     #   #             #   # #   # # #     #   # 
###.# # ######### ##### ### # # # ### ### ### # # # ##### # # # 
#  .# # #   #     #     # # # # # # #     #   # #   # #   # # # 
###.# ### ### ### # # # # # ####### # # ########### # ### # ### 
#  ...    #     # # # # # #   #     # #   #       # # #   # # # 
# # #.####### ##### ##### ### ##### # ########### # # ### # # # 
# # #.....# # # #           # #   #               #           # 
# #######.# ### ### ### # ### # ########### # ##### ####### # # 
# # #   #.........  #   #         #       # #   # #   # # # # # 
# # # ### # #####.### # # ### ######### # ####### ##### # ### # 
# # #     # #  ...#   # # #   # #       # #                   # 
# # # # ### ###.### ### ##### # # ####### ########### ##### # # 
#   # #   # #  ...# # # #     #   # #     #   # #     # # # # # 
# ####### #######.### # ####### # # # ####### # # # ### # # # # 
#       #     #  .#   # #   #   # #   #   #       # #     # # # 
# # # ####### # #.### ### # ##### # ### ### ### ####### ####### 
# # #     # # # #.# #     # #...  # #     #   # #   #...#     # 
### # ##### # ###.# ####### #.#.######### # ##### ###.#.### ### 
# # #       # #...  #   # #  .#.............#   #.....#...#   # 
# ##### #######.##### ### ###.######### ###.# ###.### ###.# ### 
# #         #  .# #  .........#         # #.#...#.#   #  .....# 
# # ### ### ###.# ###.# # # ### ######### #.#.#.#.# # #######.# 
#     # #     #.......# # # #   #          .#.#...# #   #    .# 
# ### ########### ####### ### # ##### #####.#.### ###########.# 
#   # # #   # # #   # # # #   # # #     #  ...# # # #     #...# 
### ### # ### # ##### # ######### ######### # # ### ##### #.# # 
#   # #   #       #     #     #         # # #   #   # # #  .# # 
##### # # ### # # ### ### # # # # # ##### # # # ### # # ###.### 
# # #   # #   # #   #   # # #   # # #       # # # # #     #.  # 
# # # ### ### # # ### ##### ##### ######### ##### # ##### #.# # 
#       # #   # # #         #   #     #         #          .# # 
### # ### # ####### # ##### # ############# ##### #########.# # 
#   #   #   #   #   # # #     #       # #   #   #       #  .# # 
### ### # ### ### ### # ##### ####### # ####### # #########.### 
#     # #           #   # #   #     #     # #         #    ...# 
# # ##### # ### ### ### # # ### ##### # ### ### ### #########.# 
# # #   # # #   #   # #   # #     #   # #     # #     #  .....# 
# ##### ### ####### # # ### ##### ##### ##### ##### #####.##### 
#     #   # #   #     #   #     #   #       #     # #    .  # # 
# ####### ##### ### ####### # ##### # # ##### ### #######.### # 
#       #   #   #     #     # #   #   # #       # # #.....# # # 
# ######### ### # ####### ##### ### ##### ### ### # #.##### # # 
# #     #   #   # #       # #   #     # # #     #    .....  # # 
### ### # # # # # # ####### # # # # # # # ##### ##### ###.### # 
#   #   # #   #   #   #   #   #   # #   #     #   #     #.....# 
# ####### ### # ### # # # ### ##### ### # # # # #############.# 
#   #     # # # # # #   #     # # # #     # # #         # #...# 
# # ### ### ### # ### ##### # # # # ### # ### ### ### # # #.### 
# #       # #   #   #   #   # # # # #   #   #   # #   #   #.# # 
### # ##### # ##### # ### ##### # # # ########### ##### ###.# # 
#   #       # #       #         #   # #             #     #.... 
##############################################################. 
Flag: FCSC{5cf9940286533f76743984b95c8edede9dbfde6226de012b8fe84e15f2d35e83}
```

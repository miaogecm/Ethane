#!/bin/bash

with open("input_batch_file", "w") as file:
    file.write(f"mkdir /a\n")
    for i in range(10000):
        directory = f"/a/f{i:04d}"
        file.write(f"mkdir {directory}\n")
    file.write(f"flush")

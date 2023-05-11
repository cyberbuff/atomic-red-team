import glob
import sys

import yaml

from models import AtomicTechnique

is_exception = False
for item in glob.glob("./atomics/T*/T*.yaml"):
    with open(item, 'r') as file:
        data = yaml.safe_load(file)
        try:
            AtomicTechnique(**data)
        except Exception as e:
            print(f"Error occurred with {item}.")
            print("Each of the following are why it failed:")
            print(f"\n\t{e}\n")
            is_exception = True

if is_exception:
    sys.exit(1)

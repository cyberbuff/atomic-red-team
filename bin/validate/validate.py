from models import AtomicTechnique
import glob
import yaml

for item in glob.glob("./atomics/T*/T*.yaml"):
    with open(item, 'r') as file:
        data = yaml.safe_load(file)
        try:
            AtomicTechnique(**data)
        except Exception as e:
            print(f"Error occurred with {item}.")
            print("Each of the following are why it failed:")
            print(f"\n\t{e}\n")
            raise e

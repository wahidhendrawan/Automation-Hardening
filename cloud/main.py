import argparse
import sys
import importlib
import os

# Add current directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    parser = argparse.ArgumentParser(description="Cloud Hardening Tool")
    parser.add_argument("provider", choices=["aws", "azure", "gcp"], help="Cloud provider to audit")
    args = parser.parse_args()

    print(f"[*] Starting hardening check for {args.provider.upper()}...")

    try:
        module_name = f"{args.provider}_harden"
        module = importlib.import_module(module_name)
        if hasattr(module, "run_audit"):
            module.run_audit()
        else:
            print(f"[!] Module {module_name} does not have a run_audit function.")
    except ImportError:
        print(f"[!] Could not import module {module_name}. Make sure {module_name}.py exists.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()

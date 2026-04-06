import sys
import subprocess
import importlib.util

def install(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except Exception as e:
        print(f"Failed to install {package}: {e}")

if importlib.util.find_spec("pypdf") is None:
    print("pypdf not found, installing...")
    install("pypdf")

try:
    from pypdf import PdfReader
    print("Opening PDF...")
    reader = PdfReader("cloud-security-scanner-pdr.md.pdf")
    text = ""
    print(f"Total pages: {len(reader.pages)}")
    for i, page in enumerate(reader.pages):
        try:
            content = page.extract_text()
            if content:
                text += f"\n--- Page {i+1} ---\n{content}\n"
                # print(f"Page {i+1} extracted ({len(content)} chars).")
            else:
                print(f"Page {i+1} empty.")
        except Exception as e:
            print(f"Failed to extract page {i+1}: {e}")

    output_file = "pdr_text.txt"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(text)
    
    print(f"Done. Text saved to {output_file}")

except Exception as e:
    print(f"Global error: {e}")

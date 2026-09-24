import os
from dotenv import load_dotenv

result = load_dotenv()
print(f"load_dotenv() found a file: {result}")
print(f"SUPABASE_URL: {repr(os.environ.get('SUPABASE_URL'))}")
print(f"SUPABASE_ANON_KEY: {repr(os.environ.get('SUPABASE_ANON_KEY'))}")

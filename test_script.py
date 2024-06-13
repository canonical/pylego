from guppy import hpy
from lepy import run_lego_command

hp = hpy()
print(hp.heap())

test_vars = {"namecheap_key": "bigdawg", "namecheap_name": "smalldawg"}
run_lego_command("something@gmail.com", "127.0.0.1", "/path/to/csr", "namecheap", test_vars)
before = hp.heap()

for i in range(1000000):
    run_lego_command("something@gmail.com", "127.0.0.1", "/path/to/csr", "namecheap", test_vars)

after = hp.heap()
leftover = after - before

print(leftover)
print(leftover.byrcs[0].byid)


Used python dns implementation from [here](https://implement-dns.wizardzines.com/book/part_1.html) and rewrote one part at a time in rust in order to learn the pyo3 crate.

Currently done through 2.8.


***Setup***

```bash
direnv allow    	# setup virtual env
maturin develop 	# compile and install 
./test_dns.py 		# run tests or `python -m unittest ./test_dns.py`
```


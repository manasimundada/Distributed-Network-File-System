.PHONY: ns ss client clean

ns: naming_server.c
	gcc naming_server.c -o ns
	./ns

ss: storage_server.c
	gcc storage_server.c -o ss
	./ss $(ID) -n $(IP) -p $(PORT) ./test/$(ID)

client: client.c
	gcc client.c -o client
	./client $(IP) $(PORT)


clean:
	rm -f *.o ns ss client
	rm -rf ns_folder ss0 ss1 ss2 client_folder
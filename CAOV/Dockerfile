FROM ubuntu:16.04

RUN useradd -m ctf
RUN apt-get update && apt-get install -y socat
WORKDIR /home/ctf

COPY caov ./caov
COPY ld-2.23.so ./ld-2.23.so
COPY libc_64.so.6 ./libc.so.6

# COPY --chown=ctf:ctf caov_patched ./caov
# COPY --chown=ctf:ctf libc_64.so.6 ./libc.so.6
# COPY --chown=ctf:ctf ld-2.23.so ./ld-2.23.so

RUN chmod +x ./caov ./libc.so.6 ./ld-2.23.so

USER ctf

EXPOSE 3636

CMD ["socat", "TCP-LISTEN:3636,reuseaddr,fork", "EXEC:'./ld-2.23.so --library-path . ./caov',stderr"]
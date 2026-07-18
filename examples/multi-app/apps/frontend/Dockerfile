FROM busybox:1.37.0-musl

COPY public/ /srv/

EXPOSE 8080

CMD ["httpd", "-f", "-p", "0.0.0.0:8080", "-h", "/srv"]

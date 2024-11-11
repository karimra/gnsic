FROM alpine

LABEL maintainer="Karim Radhouani <medkarimrdi@gmail.com>"
LABEL documentation="https://gnsic.kmrd.dev"
LABEL repo="https://github.com/karimra/gnsic"

COPY gnsic /app/gnsic
ENTRYPOINT [ "/app/gnsic" ]
CMD [ "help" ]

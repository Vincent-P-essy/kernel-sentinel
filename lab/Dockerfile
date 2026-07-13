FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce AS build
RUN apk add --no-cache build-base
WORKDIR /build
COPY parent.c setuid-helper.c ./
RUN cc -O2 -Wall -Wextra -Werror -o lab-parent parent.c \
    && cc -O2 -Wall -Wextra -Werror -o setuid-helper setuid-helper.c

FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce
RUN apk add --no-cache bash bind-tools curl util-linux
COPY --from=build /build/lab-parent /usr/local/bin/lab-parent
COPY --from=build /build/setuid-helper /usr/local/bin/setuid-helper
COPY run.sh /usr/local/bin/run-sentinel-lab
ENTRYPOINT ["/usr/local/bin/run-sentinel-lab"]

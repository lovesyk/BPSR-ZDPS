FROM debian:stable-slim AS libpcap-build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git build-essential bison flex autoconf automake libtool \
    && git clone https://github.com/the-tcpdump-group/libpcap.git /libpcap \
    && cd /libpcap \
    && ./autogen.sh \
    && ./configure --enable-remote \
    && make \
    && make install

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src
COPY BPSR-ZDPSLib/ BPSR-ZDPSLib/
COPY BPSR-ZDPSMessenger/ BPSR-ZDPSMessenger/
RUN dotnet publish BPSR-ZDPSMessenger/BPSR-ZDPSMessenger.csproj \
    -c Release \
    -r linux-x64 \
    --self-contained true \
    -o /app/publish

FROM debian:stable-slim
COPY --from=libpcap-build /usr/local/lib/libpcap.so* /usr/local/lib/
RUN apt-get update \
    && apt-get install -y --no-install-recommends libicu76 \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["./BPSR-ZDPSMessenger"]

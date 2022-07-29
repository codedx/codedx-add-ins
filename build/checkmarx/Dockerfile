FROM mcr.microsoft.com/powershell:lts-7.2-ubuntu-22.04

WORKDIR /opt/codedx/checkmarx/work/config
WORKDIR /opt/codedx/checkmarx/work/output

WORKDIR /opt/codedx/checkmarx/bin
COPY build/checkmarx/Checkmarx.ps1 .
COPY build/common/add-in.ps1 .

RUN apt-get update
RUN apt-get install -y curl

RUN FILE=toml2json-linux-amd64.tar.gz && \
	curl -LO https://github.com/codedx/codedx-toml2json/releases/download/v1.0.0/$FILE && \
	DEST=/opt/codedx/checkmarx/bin && \
	mkdir -p $DEST && \
	tar -C $DEST -xzf $FILE  && \
	rm $FILE

ENV PATH=/opt/codedx/checkmarx/bin:${PATH}

RUN useradd -m --shell /bin/sh checkmarx --uid 1000
RUN chown -R checkmarx:checkmarx /opt/codedx/checkmarx

USER 0

CMD ["sh"]

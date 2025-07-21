# NetTraffic

Esse repositório é dedicado ao compartilhamento do código eBPF que coleta o tráfego de interfaces de rede. Esse código foi desenvolvido como parte da disciplina de ciencia de dados que tinha o objetivo final montar um dataset. Os dados que são capturados pelo código são: IAT (inter-arrival time), tamanho do pacote, protocolo, portas e IP de origem e destino.
O código usa o hook XDP que é atrelado a uma interface. Mapas, perf events e outras esturuturas. Foi utilizada a biblioteca BCC no python para contrução do código.

## Utilização do código

Para utilizar o código você precisa:
1- Mudar a interface que deseja ser monitorada;
2- No terminal com super usuário coloque o comando ````python3 coleta_trafico.py > arquivo.csv```. Assim, toda saída capturada pelo programa será valvo no rquivo "arquivo.csv"

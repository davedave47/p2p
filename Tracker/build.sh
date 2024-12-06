docker build -t tracker .

docker run -it --network torrent-network --name tracker -v ~/Desktop/tracker:/data tracker
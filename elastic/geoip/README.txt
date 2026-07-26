GeoLite2 databases go here.

The shipper enriches events with source.geo when GeoLite2-City.mmdb is present
in this directory, which is what makes the Kibana attack map plottable.

Get one free from https://www.maxmind.com/en/geolite2/signup and drop the
extracted GeoLite2-City.mmdb alongside this file. Without it the shipper falls
back to Cloudflare's cf_ipcountry header, which only covers web traffic.

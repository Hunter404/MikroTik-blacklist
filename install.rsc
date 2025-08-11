/system script
add name=update-github-blacklist policy=read,write,test,sensitive source={
    ### CONFIG ###
    :local url "https://raw.githubusercontent.com/Hunter404/MikroTik-blacklist/main/ips.txt";
    :local dst "github-blacklist.txt";
    :local listName "github-blacklist";
    :local maxBytes 4194304;                          # 4 MiB safety cap
    :local markComment "auto:github";

    # runTag with no spaces/colons (HHMMSS)
    :local t [/system clock get time];
    :local runTag ("run-" . [:pick $t 0 2] . [:pick $t 3 5] . [:pick $t 6 8]);

    ### FETCH ###
    :do {
        /tool fetch url=$url dst-path=$dst check-certificate=yes;
    } on-error={
        :log warning ("blacklist: fetch failed from " . $url);
        :return;
    }

    ### READ FILE ###
    :if ([:len [/file find where name=$dst]] = 0) do={ :log warning "blacklist: file not found after fetch"; :return; }
    :local content [/file get $dst contents];

    ### SIZE GUARD ###
    :if ([:len $content] > $maxBytes) do={
        :log warning ("blacklist: file too large (" . [:len $content] . " bytes), aborting");
        :return;
    }

    ### HELPERS (global for reuse) ###
    :global TrimCR do={
        :local s $1;
        :if (([:len $s] > 0) and ([:pick $s ([:len $s]-1)] = "\r")) do={
            :set s [:pick $s 0 ([:len $s]-1)];
        }
        :return $s;
    };

    # IPv4 or IPv4/CIDR (0-32), no regex
    :global IsIPv4 do={
        :local s $1;
        :local slash [:find $s "/"];
        :local addr $s;
        :local pfx "";

        :if ($slash != nil) do={
            :set addr [:pick $s 0 $slash];
            :set pfx [:pick $s ($slash + 1) [:len $s]];
            :if ($pfx = "" or [:typeof [:tonum $pfx]] != "num") do={ :return false; }
            :set pfx [:tonum $pfx];
            :if ($pfx < 0 or $pfx > 32) do={ :return false; }
        }

        # must be n.n.n.n with 4 octets 0..255
        :local parts [:toarray ""];
        :local last 0;
        :while (true) do={
            :local j [:find $addr "." $last];
            :if ($j = nil) do={ :set parts ($parts, [:pick $addr $last [:len $addr]]); :break; }
            :set parts ($parts, [:pick $addr $last $j]);
            :set last ($j + 1);
        }
        :if ([:len $parts] != 4) do={ :return false; }

        :foreach oct in=$parts do={
            :if ($oct = "" or [:typeof [:tonum $oct]] != "num") do={ :return false; }
            :local n [:tonum $oct];
            :if ($n < 0 or $n > 255) do={ :return false; }
            # disallow leading plus/minus and spaces
            :if ([:len $oct] != [:len [:tostr $n]]) do={ :return false; }
        }

        :return true;
    };

    # IPv6 or IPv6/CIDR (0-128), regex-free, conservative
    :global IsIPv6 do={
        :local s $1;
        :local slash [:find $s "/"];
        :local addr $s;
        :local pfx "";

        :if ($slash != nil) do={
            :set addr [:pick $s 0 $slash];
            :set pfx [:pick $s ($slash + 1) [:len $s]];
            :if ($pfx = "" or [:typeof [:tonum $pfx]] != "num") do={ :return false; }
            :set pfx [:tonum $pfx];
            :if ($pfx < 0 or $pfx > 128) do={ :return false; }
        }

        # allowed chars only
        :local allowed "0123456789abcdefABCDEF:";
        :for i from=0 to=([:len $addr]-1) do={
            :if ([:find $allowed [:pick $addr $i]] = nil) do={ :return false; }
        }

        # must contain at least one colon
        :if ([:find $addr ":"] = nil) do={ :return false; }

        # allow a single '::'
        :local firstDouble [:find $addr "::"];
        :if ($firstDouble != nil) do={
            :if ([:find $addr "::" ($firstDouble + 2)] != nil) do={ :return false; }
        }

        # hextet lengths 1..4 (empty only if '::' present)
        :local hasDbl ($firstDouble != nil);
        :local parts [:toarray ""];
        :local last 0;
        :while (true) do={
            :local j [:find $addr ":" $last];
            :if ($j = nil) do={ :set parts ($parts, [:pick $addr $last [:len $addr]]); :break; }
            :set parts ($parts, [:pick $addr $last $j]);
            :set last ($j + 1);
        }

        :foreach h in=$parts do={
            :if ($h = "") do={
                :if (!$hasDbl) do={ :return false; }
            } else={
                :if (([:len $h] < 1) or ([:len $h] > 4)) do={ :return false; }
            }
        }

        :return true;
    };

    ### UPDATE-IN-PLACE ###
    :local added 0;
    :local updated 0;
    :local skipped 0;

    :local len [:len $content];
    :local i 0;

    :while ($i < $len) do={
        :local e [:find $content "\n" $i];
        :if ($e = nil) do={ :set e $len; }
        :local line [:pick $content $i $e];
        :set line [$TrimCR $line];
        :set i ($e + 1);

        :if (([:len $line] > 0) and ([:pick $line 0 1] != "#")) do={
            :local ok false;
            :if ([$IsIPv4 $line]) do={ :set ok true; }
            :if ([$IsIPv6 $line]) do={ :set ok true; }

            :if ($ok) do={
                :local id [/ip firewall address-list find where list=$listName and address=$line];
                :if ([:len $id] > 0) do={
                    /ip firewall address-list set $id comment=($markComment . " " . $runTag);
                    :set updated ($updated + 1);
                } else={
                    /ip firewall address-list add list=$listName address=$line comment=($markComment . " " . $runTag);
                    :set added ($added + 1);
                }
            } else={
                :set skipped ($skipped + 1);
                :log warning ("blacklist: skipping invalid entry: " . $line);
            }
        }
    }

    # PRUNE: remove old entries created by this script but not touched this run
    :local removed 0;
    :foreach id in=[/ip firewall address-list find where list=$listName] do={
        :local c [/ip firewall address-list get $id comment];
        :if (([:typeof $c] = "str") and ([:find $c $markComment] != nil) and ([:find $c $runTag] = nil)) do={
            /ip firewall address-list remove $id;
            :set removed ($removed + 1);
        }
    }

    :log info ("blacklist: added=" . $added . " updated=" . $updated . " removed=" . $removed . " skipped=" . $skipped . " list=" . $listName);
}

/system scheduler
add name=github-blacklist-update interval=7d on-event=update-github-blacklist

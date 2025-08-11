/system script
add name=update-github-blacklist policy=ftp,read,write,test,sensitive source={
    # ----- helpers -----
    :global TrimCR do={
        :local s $1
        :if (([:len $s] > 0) and ([:pick $s ([:len $s]-1)] = "\r")) do={
            :set s [:pick $s 0 ([:len $s]-1)]
        }
        :return $s
    }

    :global TrimCR

    # ----- config -----
    :local base "https://raw.githubusercontent.com/Hunter404/MikroTik-blacklist/main/"
    :local manifest "manifest.txt"
    :local listName "github-blacklist"
    :local markComment "auto:github"

    # tag with HHMMSS to avoid spaces/colons
    :local t [/system clock get time]
    :local runTag ("run-" . [:pick $t 0 2] . [:pick $t 3 5] . [:pick $t 6 8])

    # ----- fetch manifest -----
    :local manifestOk true
    :do {
        /tool fetch url=($base . $manifest) dst-path=$manifest check-certificate=yes
    } on-error={
        :set manifestOk false
    }
    :if (!$manifestOk) do={
        :log warning ("blacklist: manifest fetch failed: " . ($base . $manifest))
        :return
    }
    :if ([:len [/file find where name=$manifest]] = 0) do={
        :log warning "blacklist: manifest missing after fetch"
        :return
    }
    :local manifestContent [/file get $manifest contents]
    :if ([:len $manifestContent] = 0) do={
        :log warning "blacklist: manifest is empty"
        :return
    }

    # ----- process chunks -----
    :local added 0
    :local updated 0
    :local skipped 0

    :local mlen [:len $manifestContent]
    :local mi 0
    :while ($mi < $mlen) do={
        :local me [:find $manifestContent "\n" $mi]
        :if ($me = nil) do={ :set me $mlen }
        :local fname [:pick $manifestContent $mi $me]
        :set fname [$TrimCR $fname]
        :set mi ($me + 1)

        # skip blanks and comments
        :if (([:len $fname] > 0) and ([:pick $fname 0 1] != "#")) do={

            # fetch chunk
            :local fetched true
            :do {
                /tool fetch url=($base . $fname) dst-path=$fname check-certificate=yes
            } on-error={
                :set fetched false
            }

            :if ($fetched and ([:len [/file find where name=$fname]] > 0)) do={

                :local content [/file get $fname contents]
                :if ([:len $content] > 0) do={

                    # per-line parse (LF; CR trimmed)
                    :local len [:len $content]
                    :local i 0
                    :while ($i < $len) do={
                        :local e [:find $content "\n" $i]
                        :if ($e = nil) do={ :set e $len }
                        :local line [:pick $content $i $e]
                        :set line [$TrimCR $line]
                        :set i ($e + 1)

                        :if (([:len $line] > 0) and ([:pick $line 0 1] != "#")) do={
                            # comment used for this run
                            :local tag ($markComment . " " . $runTag)

                            # already present in IPv4?
                            :local id4 [/ip firewall address-list find where list=$listName and address=$line]
                            :if ([:len $id4] > 0) do={
                                /ip firewall address-list set $id4 comment=$tag
                                :set updated ($updated + 1)
                            } else={
                                # already present in IPv6?
                                :local id6 [/ipv6 firewall address-list find where list=$listName and address=$line]
                                :if ([:len $id6] > 0) do={
                                    /ipv6 firewall address-list set $id6 comment=$tag
                                    :set updated ($updated + 1)
                                } else={
                                    # try to add as IPv4; if that fails, try IPv6; if both fail -> skip
                                    :do {
                                        /ip firewall address-list add list=$listName address=$line comment=$tag
                                        :set added ($added + 1)
                                    } on-error={
                                        :do {
                                            /ipv6 firewall address-list add list=$listName address=$line comment=$tag
                                            :set added ($added + 1)
                                        } on-error={
                                            :set skipped ($skipped + 1)
                                            :log warning ("blacklist: cannot add (neither IPv4 nor IPv6): " . $line)
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else={
                    :log warning ("blacklist: chunk empty: " . $fname)
                }

                # remove processed chunk
                /file remove $fname

            } else={
                :log warning ("blacklist: fetch failed or file missing: " . ($base . $fname))
            }
        }
    }

    # nothing touched? skip prune to avoid wiping on bad downloads
    :if (($added + $updated) = 0) do={
        :log warning "blacklist: no entries touched; skipping prune"
        :return
    }

    # ----- prune old entries (both families) -----
    :local removed 0

    :foreach id in=[/ip firewall address-list find where list=$listName] do={
        :local c [/ip firewall address-list get $id comment]
        :if (([:typeof $c] = "str") and ([:find $c $markComment] != nil) and ([:find $c $runTag] = nil)) do={
            /ip firewall address-list remove $id
            :set removed ($removed + 1)
        }
    }
    :foreach id in=[/ipv6 firewall address-list find where list=$listName] do={
        :local c [/ipv6 firewall address-list get $id comment]
        :if (([:typeof $c] = "str") and ([:find $c $markComment] != nil) and ([:find $c $runTag] = nil)) do={
            /ipv6 firewall address-list remove $id
            :set removed ($removed + 1)
        }
    }

    :log info ("blacklist: added=" . $added . " updated=" . $updated . " removed=" . $removed . " skipped=" . $skipped . " list=" . $listName)
}

/ip firewall raw
add chain=prerouting src-address-list=github-blacklist action=drop place-before=0 comment="github-blacklist: drop SRC (v4)"
add chain=prerouting dst-address-list=github-blacklist action=drop place-before=0 comment="github-blacklist: drop DST (v4)"

/ipv6 firewall raw
add chain=prerouting src-address-list=github-blacklist action=drop place-before=0 comment="github-blacklist: drop SRC (v6)"
add chain=prerouting dst-address-list=github-blacklist action=drop place-before=0 comment="github-blacklist: drop DST (v6)"

/ip firewall address-list add list=mgmt-allow address=10.1.1.0/24
/ip firewall address-list add list=mgmt-allow address=192.168.1.0/24
/ip firewall raw add chain=prerouting src-address-list=mgmt-allow action=accept place-before=0 comment="allow mgmt (v4)"
/ipv6 firewall raw add chain=prerouting src-address-list=mgmt-allow action=accept place-before=0 comment="allow mgmt (v6)"

/system scheduler
add name=github-blacklist-update interval=7d on-event=update-github-blacklist

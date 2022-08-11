        bpf_obj = load_bpf_and_xdp_attach(&cfg);
        if (!bpf_obj)
                return EXIT_FAIL_BPF;

        if (verbose) {
                printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
                       cfg.filename, cfg.progsec);
                printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
                       cfg.ifname, cfg.ifindex);
        }

        /* Lesson#3: Locate map file descriptor */
        mapid = bpf_object__find_map_by_name(bpf_obj, "xdp_stats_map");
        stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
        if (stats_map_fd < 0) {
                xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
                return EXIT_FAIL_BPF;
        }
        if ( mapid != NULL ) {
                bpf_map__pin(mapid, "/sys/fs/bpf/xdp_stats_map");
        }
        return EXIT_OK;
}

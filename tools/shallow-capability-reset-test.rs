
#[test]
fn capabilities_are_unique_within_one_command_but_can_recur_in_the_next() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let repository = repository(format);
        let mut machine = machine(format, WireLimits::default());
        let format_line = line(format!("object-format={}", format.as_str()));
        for name in ["refs/heads/public", "refs/tags/release"] {
            machine.push_packet(&line("command=ls-refs"), &repository).unwrap();
            machine.push_packet(&format_line, &repository).unwrap();
            assert_eq!(machine.push_packet(&format_line, &repository),
                Err(WireError::DuplicateCapability { name: b"object-format".to_vec() }));
            machine.push_packet(&Packet::Delimiter, &repository).unwrap();
            machine.push_packet(&line(format!("ref-prefix {name}")), &repository).unwrap();
            let complete = machine.push_packet(&Packet::Flush, &repository).unwrap();
            assert_eq!(complete.output, expected(&repository, name));
            assert_eq!(complete.events.len(), 1);
        }
    }
}

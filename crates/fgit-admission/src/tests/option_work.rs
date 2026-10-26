//! Ordered push options cannot amplify many-ref lowering without a bound.
use super::*;

#[test]
fn repeated_options_are_bounded_before_sealing_with_atomic_and_reduced_twins() {
    let commands: Vec<_> = (0..65)
        .map(|index| create(format!("refs/tags/ref-{index:03}").as_bytes(), 7))
        .collect();
    let options =
        vec![vec![b'x'; fgit_authority::MAX_PUSH_OPTION_BYTES]; fgit_authority::MAX_PUSH_OPTIONS];
    let context = context();
    let mut request = completion(commands.clone(), false);
    request.request.push_options = options.clone();
    assert!(matches!(
        plan_session(&context, &receive_input(&request), AdmissionLimits::default()),
        Err(AdmissionError::PushOptionWorkExceeded { limit, observed })
            if limit == MAX_SESSION_OPTION_COPY_BYTES && observed > limit
    ));
    request.request.commands.pop();
    assert!(
        plan_session(
            &context,
            &receive_input(&request),
            AdmissionLimits::default()
        )
        .is_ok()
    );
    let mut atomic = completion(commands, true);
    atomic.request.push_options = options;
    assert!(
        plan_session(
            &context,
            &receive_input(&atomic),
            AdmissionLimits::default()
        )
        .is_ok()
    );
}

#[test]
fn empty_options_pay_for_repeated_headers_with_an_exact_permitted_twin() {
    let count = MAX_RECEIVE_SESSION_COMMANDS;
    let permitted_options =
        MAX_SESSION_OPTION_COPY_BYTES / (count * size_of::<fgit_authority::PushOption>());
    let commands = (0..count)
        .map(|index| create(format!("refs/tags/r{index:05}").as_bytes(), 7))
        .collect();
    let mut request = completion(commands, false);
    request.request.push_options = vec![Vec::new(); permitted_options + 1];
    assert!(matches!(
        plan_session(&context(), &receive_input(&request), AdmissionLimits::default()),
        Err(AdmissionError::PushOptionWorkExceeded { limit, observed })
            if limit == MAX_SESSION_OPTION_COPY_BYTES && observed > limit
    ));
    request.request.push_options.pop();
    assert!(
        plan_session(
            &context(),
            &receive_input(&request),
            AdmissionLimits::default()
        )
        .is_ok()
    );
}

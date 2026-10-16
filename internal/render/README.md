# Results Render Drivers

This directory contains drivers for the results renderer. More drivers can be
added by implementing the `render.Driver` interface and registering them in
the reader drivers array. Besides rendering, a driver reports which
evaluation statuses it can render through `SupportsStatus`: the terminal,
markdown, html and summary drivers render anything, while a driver that
writes an attestation answers for its format (a VSA or SVR cannot record a
`SKIP`). The CLI asks the chosen driver, and the results attester, about
every status a run may answer before evaluating, so a run never ends in
results that cannot be written. Results attestation formats are added to
`attest.ResultsAttester` with `RegisterFormat` and answer the same question.

Currently AMPEL supports the following drivers:

* `attester`: Generates an AMPEL ResultSet attestation.
* `tty`: The driver that displays results in the terminal screen.
* `html`: Renders evaluation results as HTML.
* `markdown`: Outputs the evaluation results in markdown.
* `vsa`: Renders the results set in a Verification Summary attestation.

The tty, html and markdown drivers share code through the `TableBuilder`
interface. The results output is handled by a central logic core that builds
a main table and delegates to a decorator to handle the all the
format-specific nuances.

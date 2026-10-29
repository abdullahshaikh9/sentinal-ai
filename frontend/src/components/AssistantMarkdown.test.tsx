import { render, screen } from "@testing-library/react";
import { AssistantMarkdown } from "./AssistantMarkdown";

describe("AssistantMarkdown", () => {
  it("renders escaped headings, lists, emphasis, inline code, and paragraphs", () => {
    const content = String.raw`\### Confirmed observations

\*\*Observed\*\*: the response includes a header check.

\- Set the header after validating HTTPS.
\- Retest the configured endpoint.

Use \`Strict-Transport-Security\` for this control.`;
    render(<AssistantMarkdown content={content} />);

    expect(screen.getByRole("heading", { level: 3, name: "Confirmed observations" })).toBeInTheDocument();
    expect(screen.getByText("Observed")).toBeInTheDocument();
    expect(screen.getByText("Observed").tagName).toBe("STRONG");
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("Set the header after validating HTTPS.")).toBeInTheDocument();
    expect(screen.getByText("Strict-Transport-Security").tagName).toBe("CODE");
    expect(screen.getByText(/for this control\./)).toBeInTheDocument();
  });

  it("preserves fenced code and renders raw HTML as text, not markup", () => {
    render(<AssistantMarkdown content={'Example:\n\n```html\n<img src=x onerror="alert(1)">\n```'} />);
    expect(screen.getByText('<img src=x onerror="alert(1)">')).toBeInTheDocument();
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
    expect(screen.getByText('<img src=x onerror="alert(1)">').closest("pre")).toBeInTheDocument();
  });
});

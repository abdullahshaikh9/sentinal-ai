import type { ReactNode } from "react";

function normalizeEscapedMarkdownLine(line: string): string {
  return line
    .replace(/^(\s*)\\(?=#{1,6}\s)/, "$1")
    .replace(/^(\s*)\\(?=[-*+]\s)/, "$1")
    .replace(/^(\s*)\\(?=\d+\.\s)/, "$1")
    .replace(/\\(?=[*_`])/g, "");
}

function renderInline(value: string, keyPrefix: string): ReactNode[] {
  const pattern = /(`[^`\n]+`|\*\*.+?\*\*|__.+?__|\*[^*\n]+\*|_[^_\n]+_)/g;
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(value)) !== null) {
    if (match.index > cursor) nodes.push(value.slice(cursor, match.index));
    const token = match[0];
    const key = `${keyPrefix}-${match.index}`;
    if (token.startsWith("`")) {
      nodes.push(<code key={key} className="rounded bg-white/10 px-1 py-0.5 font-mono text-[0.9em] text-inherit">{token.slice(1, -1)}</code>);
    } else if (token.startsWith("**") || token.startsWith("__")) {
      nodes.push(<strong key={key} className="font-semibold text-inherit">{renderInline(token.slice(2, -2), key)}</strong>);
    } else {
      nodes.push(<em key={key}>{renderInline(token.slice(1, -1), key)}</em>);
    }
    cursor = match.index + token.length;
  }

  if (cursor < value.length) nodes.push(value.slice(cursor));
  return nodes;
}

function isBlockStart(lines: string[], index: number): boolean {
  const line = normalizeEscapedMarkdownLine(lines[index] ?? "");
  return /^\s{0,3}(#{1,6})\s+/.test(line)
    || /^\s{0,3}(```|~~~)/.test(line)
    || /^\s{0,3}[-*_]{3,}\s*$/.test(line)
    || /^\s*[-*+]\s+/.test(line)
    || /^\s*\d+\.\s+/.test(line);
}

export function AssistantMarkdown({ content }: { content: string }) {
  const lines = content.replace(/\r\n?/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let index = 0;

  while (index < lines.length) {
    const line = normalizeEscapedMarkdownLine(lines[index]);
    if (!line.trim()) { index += 1; continue; }

    const fence = line.match(/^\s{0,3}(```+|~~~+)/);
    if (fence) {
      const marker = fence[1][0];
      index += 1;
      const code: string[] = [];
      while (index < lines.length && !new RegExp(`^\\s{0,3}${marker}{3,}\\s*$`).test(lines[index])) {
        code.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push(<pre key={`code-${blocks.length}`} className="overflow-x-auto rounded-lg bg-slate-900 p-3 font-mono text-xs text-slate-100"><code>{code.join("\n")}</code></pre>);
      continue;
    }

    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.+?)\s*#*\s*$/);
    if (heading) {
      const level = heading[1].length;
      const className = "font-semibold text-inherit";
      const children = renderInline(heading[2], `heading-${blocks.length}`);
      if (level === 1) blocks.push(<h1 key={`h-${blocks.length}`} className={`text-xl ${className}`}>{children}</h1>);
      else if (level === 2) blocks.push(<h2 key={`h-${blocks.length}`} className={`text-lg ${className}`}>{children}</h2>);
      else if (level === 3) blocks.push(<h3 key={`h-${blocks.length}`} className={`text-base ${className}`}>{children}</h3>);
      else if (level === 4) blocks.push(<h4 key={`h-${blocks.length}`} className={className}>{children}</h4>);
      else if (level === 5) blocks.push(<h5 key={`h-${blocks.length}`} className={className}>{children}</h5>);
      else blocks.push(<h6 key={`h-${blocks.length}`} className={className}>{children}</h6>);
      index += 1;
      continue;
    }

    if (/^\s{0,3}([-*_])\1{2,}\s*$/.test(line)) {
      blocks.push(<hr key={`hr-${blocks.length}`} className="border-slate-200" />);
      index += 1;
      continue;
    }

    const unordered = line.match(/^\s*[-*+]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+\.\s+(.+)$/);
    if (unordered || ordered) {
      const listType = unordered ? "unordered" : "ordered";
      const items: string[] = [];
      while (index < lines.length) {
        const itemLine = normalizeEscapedMarkdownLine(lines[index]);
        const item = listType === "unordered"
          ? itemLine.match(/^\s*[-*+]\s+(.+)$/)
          : itemLine.match(/^\s*\d+\.\s+(.+)$/);
        if (!item) break;
        items.push(item[1]);
        index += 1;
      }
      const renderedItems = items.map((item, itemIndex) => <li key={`li-${itemIndex}`}>{renderInline(item, `list-${blocks.length}-${itemIndex}`)}</li>);
      if (listType === "unordered") blocks.push(<ul key={`ul-${blocks.length}`} className="list-disc space-y-1 pl-6">{renderedItems}</ul>);
      else blocks.push(<ol key={`ol-${blocks.length}`} className="list-decimal space-y-1 pl-6">{renderedItems}</ol>);
      continue;
    }

    const paragraph = [line];
    index += 1;
    while (index < lines.length && lines[index].trim() && !isBlockStart(lines, index)) {
      paragraph.push(normalizeEscapedMarkdownLine(lines[index]));
      index += 1;
    }
    blocks.push(<p key={`p-${blocks.length}`} className="whitespace-pre-wrap">{renderInline(paragraph.join("\n"), `paragraph-${blocks.length}`)}</p>);
  }

  return <div className="space-y-3">{blocks}</div>;
}

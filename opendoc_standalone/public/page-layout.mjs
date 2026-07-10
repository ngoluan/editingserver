export function getPageMetrics(pageSize = 'letter', orientation = 'portrait') {
  const base = pageSize === 'a4' ? { widthIn: 8.27, heightIn: 11.69 } : { widthIn: 8.5, heightIn: 11 };
  return orientation === 'landscape' ? { widthIn: base.heightIn, heightIn: base.widthIn } : base;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

function resolveStyle(block, styles = {}) {
  const visited = new Set();
  const merge = styleId => {
    if (!styleId || visited.has(styleId)) return {};
    visited.add(styleId);
    const style = styles[styleId] || {};
    return { ...merge(style.basedOn), ...style };
  };
  return merge(block.style || 'normal');
}

function objectTransform(block) {
  const sx = block.image?.flipX ? -1 : 1;
  const sy = block.image?.flipY ? -1 : 1;
  return `rotate(${Number(block.layout?.rotation || 0)}deg) scale(${sx},${sy})`;
}

function objectImageHtml(block) {
  const image = block.image || {};
  const crop = image.crop || {};
  const left = Math.max(0, Math.min(.95, Number(crop.left || 0)));
  const right = Math.max(0, Math.min(.95, Number(crop.right || 0)));
  const top = Math.max(0, Math.min(.95, Number(crop.top || 0)));
  const bottom = Math.max(0, Math.min(.95, Number(crop.bottom || 0)));
  const visibleWidth = Math.max(.05, 1 - left - right);
  const visibleHeight = Math.max(.05, 1 - top - bottom);
  const filters = image.filters || {};
  const imgStyle = `width:${100 / visibleWidth}%;height:${100 / visibleHeight}%;left:${-left / visibleWidth * 100}%;top:${-top / visibleHeight * 100}%;filter:brightness(${filters.brightness ?? 1}) contrast(${filters.contrast ?? 1}) saturate(${filters.saturate ?? 1}) grayscale(${filters.grayscale ?? 0}) sepia(${filters.sepia ?? 0});opacity:${filters.opacity ?? 1};`;
  const border = image.border || {};
  const viewportStyle = `border:${Number(border.width || 0)}px ${esc(border.style || 'solid')} ${esc(border.color || 'transparent')};border-radius:${Number(image.cornerRadius || 0)}px;${image.shadow ? `box-shadow:${esc(image.shadow)};` : ''}`;
  return `<div class="print-object-image" style="${viewportStyle}"><img src="${esc(image.src || '')}" alt="${image.decorative ? '' : esc(image.altText || '')}" style="${imgStyle}"></div>${image.caption ? `<figcaption>${esc(image.caption)}</figcaption>` : ''}`;
}

function objectTextBoxHtml(block) {
  const textBox = block.textBox || {};
  const margins = textBox.margins || {};
  const appearance = block.appearance || {};
  const content = (textBox.blocks || []).map(item => item.content || '').join('<div><br></div>');
  const style = `padding:${Number(margins.top || 0)}px ${Number(margins.right || 0)}px ${Number(margins.bottom || 0)}px ${Number(margins.left || 0)}px;column-count:${Math.max(1, Number(textBox.columns || 1))};background:${esc(appearance.fill || 'transparent')};border:${Number(appearance.borderWidth || 0)}px ${esc(appearance.borderStyle || 'solid')} ${esc(appearance.borderColor || 'transparent')};border-radius:${Number(appearance.cornerRadius || 0)}px;opacity:${appearance.opacity ?? 1};${appearance.shadow ? `box-shadow:${esc(appearance.shadow)};` : ''}`;
  return `<div class="print-text-box vertical-${esc(textBox.verticalAlign || 'top')}" style="${style}">${content}</div>`;
}

function objectToHtml(block) {
  const layout = block.layout || {};
  const wrap = block.wrap || {};
  const distance = wrap.distance || {};
  const inline = layout.mode === 'inline' || (wrap.type || 'inline') === 'inline';
  const wrapProxy = !inline && ['square', 'topBottom', 'tight', 'through'].includes(wrap.type || '');
  const classes = `print-object object-${esc(block.objectType)} wrap-${esc(wrap.type || 'inline')} ${inline ? 'flow-object' : 'positioned-object'}`;
  let style = `width:${Number(layout.width || 240)}px;${layout.height ? `height:${Number(layout.height)}px;` : ''}transform:${objectTransform(block)};z-index:${Number(layout.zIndex || 1)};`;
  if (inline) {
    style += `margin:${Number(distance.top || 0)}px ${Number(distance.right || 0)}px ${Number(distance.bottom || 0)}px ${Number(distance.left || 0)}px;`;
  } else {
    style += `left:${Number(layout.x || 0)}px;top:${Number(layout.y || 0)}px;margin:0;`;
  }

  let proxy = '';
  if (wrapProxy) {
    const side = wrap.side === 'left' ? 'right' : wrap.side === 'right' ? 'left' : (Number(layout.x || 0) > 260 ? 'right' : 'left');
    const width = Math.max(24, Number(layout.width || 240));
    const height = Math.max(24, Number(layout.height || 120));
    let proxyStyle = `width:${width}px;height:${height}px;margin-top:${Math.max(0, Number(layout.y || 0) - Number(distance.top || 0))}px;margin-right:${Number(distance.right || 0)}px;margin-bottom:${Number(distance.bottom || 0)}px;margin-left:${Number(distance.left || 0)}px;`;
    if (wrap.type === 'topBottom') proxyStyle += 'float:none;clear:both;width:100%;';
    else {
      proxyStyle += `float:${side};shape-margin:${Math.max(Number(distance.top || 0), Number(distance.right || 0), Number(distance.bottom || 0), Number(distance.left || 0))}px;`;
      if (Array.isArray(wrap.contour) && wrap.contour.length >= 3) proxyStyle += `shape-outside:polygon(${wrap.contour.map(point => `${Number(point.x) * 100}% ${Number(point.y) * 100}%`).join(',')});`;
      else if ((wrap.type === 'tight' || wrap.type === 'through') && block.objectType === 'image' && block.image?.src) proxyStyle += `shape-outside:url("${esc(block.image.src)}");shape-image-threshold:.1;`;
      else proxyStyle += 'shape-outside:margin-box;';
    }
    proxy = `<div class="print-wrap-proxy print-wrap-proxy-${esc(wrap.type)}" aria-hidden="true" style="${proxyStyle}"></div>`;
  }

  const content = block.objectType === 'image' ? objectImageHtml(block) : objectTextBoxHtml(block);
  return `${proxy}<div data-block-id="${esc(block.id)}" class="${classes}" style="${style}"><div class="print-object-frame">${content}</div></div>`;
}

export function blockToHtml(block, context = {}) {
  const styles = context.styles || {};
  if (block.type === 'text') {
    const named = resolveStyle(block, styles);
    const fontFamily = block.fontFamily || named.fontFamily || 'Segoe UI';
    const fontSize = block.fontSize || named.fontSize || 12;
    const lineHeight = block.lineHeight || named.lineHeight || 1.5;
    const spacingAfter = block.marginBottom ?? named.spacingAfter ?? 6;
    let css = `font-family:"${esc(fontFamily)}",Arial,sans-serif;font-size:${fontSize}pt;line-height:${lineHeight};margin:0 0 ${spacingAfter}pt;position:relative;`;
    if (named.bold) css += 'font-weight:700;';
    if (named.italic) css += 'font-style:italic;';
    if (named.color) css += `color:${esc(named.color)};`;
    if (block.style === 'h1') css += 'font-size:24pt;font-weight:700;color:#2b579a;margin-top:20px;';
    else if (block.style === 'h2') css += 'font-size:18pt;font-weight:700;color:#444;margin-top:15px;';
    else if (block.style === 'h3') css += 'font-size:14pt;font-weight:700;color:#444;margin-top:12px;';
    else if (block.style === 'quote') css += 'font-style:italic;border-left:4px solid #ccc;padding-left:10px;color:#555;';
    if (block.align) css += `text-align:${block.align};`;
    if (block.indent) css += `padding-left:${Number(block.indent) * 20}px;`;
    if (block.marginTop) css += `margin-top:${Number(block.marginTop)}pt;`;
    if (block.keepLinesTogether || named.keepLinesTogether) css += 'break-inside:avoid;';
    if (block.keepWithNext || named.keepWithNext) css += 'break-after:avoid;';
    css += `orphans:${Math.max(1, Number(block.orphanLines || named.orphanLines || 2))};widows:${Math.max(1, Number(block.widowLines || named.widowLines || 2))};`;
    return `<div data-block-id="${esc(block.id)}" style="${css}">${block.content || ''}</div>`;
  }
  if (block.type === 'pageBreak') return '<div class="explicit-page-break"></div>';
  if (block.type === 'sectionBreak') return '';
  if (['ul', 'ol', 'checklist'].includes(block.type)) {
    if (block.type === 'checklist') {
      const items = (block.items || []).map(item => `<li style="list-style:none">${item.checked ? '&#9745;' : '&#9744;'} ${item.text || ''}</li>`).join('');
      return `<ul data-block-id="${esc(block.id)}" class="checklist">${items}</ul>`;
    }
    const items = (block.items || []).map(item => `<li>${item.text || ''}</li>`).join('');
    return `<${block.type} data-block-id="${esc(block.id)}">${items}</${block.type}>`;
  }
  if (block.type === 'horizontalRule') return `<hr data-block-id="${esc(block.id)}">`;
  if (block.type === 'table') {
    const renderedRows = (block.rows || []).map((row, rowIndex) => {
      const cells = [];
      row.forEach((content, colIndex) => {
        const cellId = block.cellIds?.[rowIndex]?.[colIndex];
        const meta = block.cellMeta?.[cellId] || {};
        if (meta.coveredBy) return;
        const tag = (block.headerRows || 0) > rowIndex ? 'th' : 'td';
        const spans = `${meta.rowspan > 1 ? ` rowspan="${meta.rowspan}"` : ''}${meta.colspan > 1 ? ` colspan="${meta.colspan}"` : ''}`;
        cells.push(`<${tag}${spans}>${content || ''}</${tag}>`);
      });
      return `<tr>${cells.join('')}</tr>`;
    });
    const headerCount = Math.max(0, Math.min(renderedRows.length, Number(block.headerRows || 0)));
    return `<table data-block-id="${esc(block.id)}">${headerCount ? `<thead>${renderedRows.slice(0, headerCount).join('')}</thead>` : ''}<tbody>${renderedRows.slice(headerCount).join('')}</tbody></table>`;
  }
  if (block.type === 'object') return objectToHtml(block);
  if (block.type === 'image') {
    const align = block.align || 'center';
    const margin = align === 'center' ? '0 auto' : align === 'right' ? '0 0 0 auto' : '0';
    return `<figure data-block-id="${esc(block.id)}" style="width:${Number(block.width || 100)}%;margin:${margin}"><img src="${esc(block.content)}">${block.caption ? `<figcaption>${esc(block.caption)}</figcaption>` : ''}</figure>`;
  }
  if (block.type === 'toc') return '<section class="toc"><strong>Table of Contents</strong></section>';
  if (block.type === 'footnote' || block.type === 'endnote') return `<div class="document-note"><sup>${esc(block.fnNumber || block.enNumber || '')}</sup> ${block.content || ''}</div>`;
  if (block.type === 'floating') {
    const content = block.subType === 'image' ? `<img src="${esc(block.content)}">` : `<div>${block.content || ''}</div>`;
    return `<div class="floating" style="left:${Number(block.x || 0)}px;top:${Number(block.y || 0)}px;width:${Number(block.w || 100)}px;height:${Number(block.h || 100)}px">${content}</div>`;
  }
  return '';
}

function splitIntoSections(blocks, settings, doc) {
  const declared = doc?.sections || [];
  const initial = declared[0] || {};
  const groups = [{ id: initial.id || 'section-default', settings: initial.settings || settings || {}, header: initial.header || doc?.header, footer: initial.footer || doc?.footer, blocks: [] }];
  (blocks || []).forEach(block => {
    if (block.type === 'sectionBreak') {
      const declaredSection = declared.find(section => section.id === block.sectionId) || {};
      groups.push({ id: block.sectionId || `section-${groups.length + 1}`, settings: declaredSection.settings || block.settings || settings || {}, header: declaredSection.header || doc?.header, footer: declaredSection.footer || doc?.footer, blocks: [] });
    } else groups[groups.length - 1].blocks.push(block);
  });
  return groups;
}

function footerHtml(value) {
  if (!value) return '';
  return String(value).split('{n}').map((part, index, values) => `${esc(part)}${index < values.length - 1 ? '<span class="page-number-field"></span>' : ''}`).join('');
}

export function generatePageHtml(blocks, settings, doc) {
  const sections = splitIntoSections(blocks, settings, doc);
  const pageRules = sections.map((section, index) => {
    const current = section.settings || {};
    const metrics = getPageMetrics(current.pageSize || settings?.pageSize || 'letter', current.orientation || 'portrait');
    return `@page section-${index} { size:${metrics.widthIn}in ${metrics.heightIn}in; margin:0; }`;
  }).join('\n');
  const sectionHtml = sections.map((section, index) => {
    const current = section.settings || {};
    const metrics = getPageMetrics(current.pageSize || settings?.pageSize || 'letter', current.orientation || 'portrait');
    const margins = current.margins || settings?.margins || { top: 1, right: 1, bottom: 1, left: 1 };
    const columns = Math.max(1, Number(current.columns || 1));
    return `<section class="document-section" style="--page-width:${metrics.widthIn}in;--page-height:${metrics.heightIn}in;--margin-top:${margins.top}in;--margin-right:${margins.right}in;--margin-bottom:${margins.bottom}in;--margin-left:${margins.left}in;page:section-${index}">
      ${section.header?.center ? `<header class="section-header">${esc(section.header.center)}</header>` : ''}
      <main class="section-content" style="column-count:${columns}">${section.blocks.map(block => blockToHtml(block, { styles: doc?.styles || {} })).join('\n')}</main>
      ${section.footer?.center ? `<footer class="section-footer">${footerHtml(section.footer.center)}</footer>` : ''}
    </section>`;
  }).join('\n');

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><style>
    ${pageRules}
    html,body{margin:0;padding:0;background:white;font-family:"Segoe UI",Arial,sans-serif;counter-reset:page}
    *{box-sizing:border-box}.document-section{width:var(--page-width);min-height:var(--page-height);padding:var(--margin-top) var(--margin-right) var(--margin-bottom) var(--margin-left);position:relative;break-after:page;counter-increment:page}.document-section:last-child{break-after:auto}
    .section-header{font-size:9pt;color:#777;text-align:center;margin-bottom:18px}.section-footer{font-size:9pt;color:#777;text-align:center;position:absolute;left:var(--margin-left);right:var(--margin-right);bottom:.3in}.page-number-field::after{content:counter(page)}
    .explicit-page-break{break-before:page;height:0}.section-content{column-gap:.35in;position:relative;min-height:1px}img{max-width:100%;height:auto}figure{margin-top:8px;margin-bottom:8px}figcaption{text-align:center;font-size:10pt;color:#666}
    table{width:100%;border-collapse:collapse;break-inside:auto}tr{break-inside:avoid}thead{display:table-header-group}th,td{border:1px solid #999;padding:5px;vertical-align:top}th{background:#eaf2f8;font-weight:700}ul,ol{font-size:12pt;margin:0 0 10px 0}.checklist{padding-left:0}hr{border:0;border-top:1px solid #777;margin:12px 0}.document-note{font-size:10pt;color:#555;margin-bottom:4px}.floating,.positioned-object{position:absolute;overflow:visible}.floating img{width:100%;height:100%;object-fit:contain}.print-object{position:relative;max-width:100%;transform-origin:center}.print-object.positioned-object{position:absolute}.print-object.flow-object{position:relative}.print-wrap-proxy{display:block;opacity:0;visibility:hidden;pointer-events:none;overflow:hidden}.print-wrap-proxy-topBottom{float:none!important}.print-object-frame{width:100%;height:100%;position:relative}.print-object-image{width:100%;height:100%;position:relative;overflow:hidden}.print-object-image img{position:absolute;max-width:none;object-fit:cover}.print-text-box{width:100%;height:100%;overflow:hidden}.vertical-middle{display:flex;flex-direction:column;justify-content:center}.vertical-bottom{display:flex;flex-direction:column;justify-content:flex-end}.wrap-behindText{z-index:0}.wrap-inFrontOfText{z-index:30}.wrap-topBottom{display:block;clear:both}code{font-family:Consolas,monospace;background:#f0f0f0;color:#c7254e;padding:1px 4px;border-radius:3px}ins{color:#2e7d32;text-decoration:underline}del{color:#c62828;text-decoration:line-through}
  </style></head><body>${sectionHtml}</body></html>`;
}

<?xml version="1.0"?>
<!--
  Man page stylesheet for the classic Python asciidoc (asciidoc-py) backend,
  used by cmake/Modules/AdocMan.cmake as the asciidoctor alternative (#2395).

  Imports the stock docbook-xsl manpages stylesheet (resolved through the
  system XML catalog, never the network) and applies the same adjustments
  as a2x's bundled manpage.xsl, plus the hard line break handling git needs
  in its own dual-toolchain setup:
    - `<?asciidoc-br?>` (asciidoc's `+` line break) becomes a roff .br
      request; stock docbook-xsl drops it silently;
    - ulink renders text only, without the auto-generated REFERENCES list;
    - progress notes are silenced.
-->
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
<xsl:import href="http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl"/>

<xsl:param name="man.output.quietly" select="1"/>
<xsl:param name="refentry.meta.get.quietly" select="1"/>

<xsl:template match="processing-instruction('asciidoc-br')">
<xsl:text>.br
</xsl:text>
</xsl:template>

<!-- Only render the link text, no auto-generated REFERENCES section. -->
<xsl:template match="ulink">
  <xsl:variable name="content">
    <xsl:apply-templates/>
  </xsl:variable>
  <xsl:value-of select="$content"/>
</xsl:template>
<xsl:template name="endnotes.list"></xsl:template>
<xsl:template name="format.links.list"></xsl:template>

</xsl:stylesheet>

// components/Providers.js
"use client";
import { TerminalProvider } from "../contexts/TerminalContext";
import { VMProvider } from "../contexts/VMContext";
import { CommandProcessorProvider } from "../contexts/CommandProcessorContext";
import { AIChatProvider } from "../contexts/AIChatContext";
import { NmapProvider } from "../contexts/NmapContext";
import { PhishingProvider } from "../contexts/PhishingContext";


export default function Providers({ children }) {
  return (
    <TerminalProvider>
      <VMProvider>
        <CommandProcessorProvider>
          <AIChatProvider>
            <NmapProvider>
              <PhishingProvider>
                {children}
              </PhishingProvider>
            </NmapProvider>
          </AIChatProvider>
        </CommandProcessorProvider>
      </VMProvider>
    </TerminalProvider>
  );
}
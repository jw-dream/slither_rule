from typing import List

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.utils.output import Output
from slither.slithir.operations import InternalCall, LibraryCall
import re

class PerpetualCloseFunctionDetector(AbstractDetector):
    ARGUMENT = "Perpetual-Open-Detect"
    HELP = "logic Check in perpetual protocol"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.LOW

    WIKI = "https://github.com/perpetual-protocol/perp-curie-contract/blob/80a3050914a846939bfd98ad9e379762f8d75626/contracts/ClearingHouse.sol#L338"
    WIKI_TITLE = "logic example"
    WIKI_DESCRIPTION = "logic example"
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    def _detect(self) -> List[Output]:
        results = []
        set1 = []
        set2 = []

        for contract in self.compilation_unit.contracts:
            for function in contract.functions:
                if function.visibility in ['external']:
                    if self.has_modifier(function): set1.append(function.name)
                    for node in function.nodes:
                        for ir in node.irs:
                            if self.has_internal_call_with_return(ir) and self.count_internal_calls(node) == 1: set2.append(node.function.name)

        matches = set(set1) & set(set2)


        results.append(self.generate_result("[Find OpenPosition Function]\n"))
        for match in matches:
            info = ["- ", match, "\n"]
            res = self.generate_result(info)
            results.append(res)
        results.append(self.generate_result("\n"))
        return results

    @staticmethod
    def has_internal_call_with_return(ir):
        if isinstance(ir, InternalCall):
            if (len(ir.function.returns) == 2):
                return ir

    @staticmethod
    def has_modifier(function):
        if function.modifiers:
            return True
        return False
    
    @staticmethod
    def count_internal_calls(node):
        count = 0
        for ir in node.irs:
            if isinstance(ir, InternalCall):
                count += 1
        return count

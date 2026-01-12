#include "ProvenanceTracker.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "Util/SVFUtil.h"
#include <llvm/IR/Instructions.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/DerivedTypes.h>

using namespace SVF;
using namespace llvm;

// 静态成员初始化：标准allocator函数
std::set<std::string> ProvenanceTracker::standard_allocators = {
    "malloc",
    "calloc",
    "realloc",
    "strdup",
    "strndup"
};

// 静态成员初始化：自定义allocator模式（后缀匹配）
std::set<std::string> ProvenanceTracker::custom_allocator_patterns = {
    "_new",
    "_New",
    "_NEW",
    "_create",
    "_Create",
    "_CREATE",
    "_alloc",
    "_Alloc",
    "_ALLOC",
    "_allocate",
    "_Allocate",
    "_init",
    "_Init",
    "_INIT"
};

bool ProvenanceTracker::isStandardAllocator(const std::string& func_name) const {
    return standard_allocators.find(func_name) != standard_allocators.end();
}

bool ProvenanceTracker::isCustomAllocator(const std::string& func_name) const {
    // 检查是否包含allocator后缀模式
    for (const auto& pattern : custom_allocator_patterns) {
        if (func_name.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool ProvenanceTracker::isOpaquePointer(const llvm::Type* return_type) const {
    if (!return_type || !return_type->isPointerTy()) {
        return false;
    }

    // 获取指针指向的类型
    auto pointed_type = llvm::cast<llvm::PointerType>(return_type)->getElementType();

    // 检查是否是opaque struct（forward declaration）
    if (auto struct_type = llvm::dyn_cast<llvm::StructType>(pointed_type)) {
        // Opaque struct没有body定义
        return struct_type->isOpaque();
    }

    // 检查是否是不完整类型
    if (!pointed_type->isSized()) {
        return true;
    }

    return false;
}

ProvenanceInfo ProvenanceTracker::analyzeCallReturnValue(const llvm::CallInst* call) const {
    if (!call) {
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    // 获取被调用函数
    const llvm::Function* callee = call->getCalledFunction();
    if (!callee) {
        // 间接调用，无法确定provenance
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    std::string func_name = callee->getName().str();

    // 检查是否是标准allocator
    if (isStandardAllocator(func_name)) {
        return ProvenanceInfo(ProvenanceTag::HEAP_MALLOC, call->getType());
    }

    // 检查是否是自定义allocator
    if (isCustomAllocator(func_name)) {
        return ProvenanceInfo(ProvenanceTag::HEAP_CUSTOM, func_name, call->getType());
    }

    // 检查返回类型是否是opaque指针
    if (isOpaquePointer(call->getType())) {
        return ProvenanceInfo(ProvenanceTag::RETURN_OPAQUE, call->getType());
    }

    // 默认情况：函数返回的指针类型未知
    return ProvenanceInfo(ProvenanceTag::UNKNOWN, call->getType());
}

ProvenanceInfo ProvenanceTracker::analyzeParameter(const llvm::Argument* arg) const {
    if (!arg) {
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    // 参数都被认为是借用的（从调用者传入）
    return ProvenanceInfo(ProvenanceTag::PARAM_BORROWED, arg->getType());
}

ProvenanceInfo ProvenanceTracker::analyzeStackAllocation(const llvm::AllocaInst* alloca) const {
    if (!alloca) {
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    // AllocaInst是栈上分配
    return ProvenanceInfo(ProvenanceTag::STACK, alloca->getType());
}

ProvenanceInfo ProvenanceTracker::analyzeGlobalVariable(const llvm::GlobalVariable* gv) const {
    if (!gv) {
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    // 全局变量
    return ProvenanceInfo(ProvenanceTag::GLOBAL, gv->getType());
}

ProvenanceInfo ProvenanceTracker::analyzePointerSource(const llvm::Value* ptr) const {
    if (!ptr) {
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    // 尝试使用SVF的points-to分析追踪指针来源
    // 这里简化实现：直接分析Value的类型

    if (const auto* call_inst = llvm::dyn_cast<llvm::CallInst>(ptr)) {
        return analyzeCallReturnValue(call_inst);
    }

    if (const auto* arg = llvm::dyn_cast<llvm::Argument>(ptr)) {
        return analyzeParameter(arg);
    }

    if (const auto* alloca = llvm::dyn_cast<llvm::AllocaInst>(ptr)) {
        return analyzeStackAllocation(alloca);
    }

    if (const auto* gv = llvm::dyn_cast<llvm::GlobalVariable>(ptr)) {
        return analyzeGlobalVariable(gv);
    }

    // Load/Store/GEP等指令：追踪其操作数
    if (const auto* load_inst = llvm::dyn_cast<llvm::LoadInst>(ptr)) {
        return analyzePointerSource(load_inst->getPointerOperand());
    }

    if (const auto* gep_inst = llvm::dyn_cast<llvm::GetElementPtrInst>(ptr)) {
        return analyzePointerSource(gep_inst->getPointerOperand());
    }

    if (const auto* bitcast_inst = llvm::dyn_cast<llvm::BitCastInst>(ptr)) {
        return analyzePointerSource(bitcast_inst->getOperand(0));
    }

    // PHINode：选择第一个incoming value（简化处理）
    if (const auto* phi_node = llvm::dyn_cast<llvm::PHINode>(ptr)) {
        if (phi_node->getNumIncomingValues() > 0) {
            return analyzePointerSource(phi_node->getIncomingValue(0));
        }
    }

    // 默认：未知来源
    return ProvenanceInfo(ProvenanceTag::UNKNOWN);
}

ProvenanceInfo ProvenanceTracker::analyze(const llvm::Value* value) const {
    return analyzePointerSource(value);
}

ProvenanceInfo ProvenanceTracker::analyzeReturnValue(const llvm::Function* func) const {
    if (!func || func->isDeclaration()) {
        return ProvenanceInfo(ProvenanceTag::UNKNOWN);
    }

    std::string func_name = func->getName().str();

    // 检查是否是标准allocator
    if (isStandardAllocator(func_name)) {
        return ProvenanceInfo(ProvenanceTag::HEAP_MALLOC, func->getReturnType());
    }

    // 检查是否是自定义allocator
    if (isCustomAllocator(func_name)) {
        return ProvenanceInfo(ProvenanceTag::HEAP_CUSTOM, func_name, func->getReturnType());
    }

    // 检查返回类型是否是opaque指针
    if (isOpaquePointer(func->getReturnType())) {
        return ProvenanceInfo(ProvenanceTag::RETURN_OPAQUE, func->getReturnType());
    }

    // 分析函数体中的return语句
    for (const auto& BB : *func) {
        for (const auto& Inst : BB) {
            if (const auto* ret_inst = llvm::dyn_cast<llvm::ReturnInst>(&Inst)) {
                if (auto* ret_value = ret_inst->getReturnValue()) {
                    // 分析返回值的provenance
                    return analyzePointerSource(ret_value);
                }
            }
        }
    }

    return ProvenanceInfo(ProvenanceTag::UNKNOWN, func->getReturnType());
}

bool ProvenanceTracker::isCompatible(const ProvenanceInfo& source,
                                     const ProvenanceInfo& sink) {
    // 过滤规则：
    // 1. HEAP_MALLOC 不能传给 RETURN_OPAQUE 参数
    if (source.tag == ProvenanceTag::HEAP_MALLOC &&
        sink.tag == ProvenanceTag::RETURN_OPAQUE) {
        return false;
    }

    // 2. PARAM_BORROWED 不能传给需要释放的API（这需要后续通过Access信息判断）
    // 这里简化：假设所有PARAM_BORROWED都是安全的

    // 3. RETURN_OPAQUE 可以传给同类型的 RETURN_OPAQUE 参数
    if (source.tag == ProvenanceTag::RETURN_OPAQUE &&
        sink.tag == ProvenanceTag::RETURN_OPAQUE) {
        // TODO: 检查类型是否匹配
        return true;
    }

    // 4. HEAP_CUSTOM 可以传给 RETURN_OPAQUE（库内部分配的对象）
    if (source.tag == ProvenanceTag::HEAP_CUSTOM &&
        sink.tag == ProvenanceTag::RETURN_OPAQUE) {
        return true;
    }

    // 5. UNKNOWN 保守处理：允许
    if (source.tag == ProvenanceTag::UNKNOWN ||
        sink.tag == ProvenanceTag::UNKNOWN) {
        return true;
    }

    // 6. 相同tag通常兼容
    if (source.tag == sink.tag) {
        return true;
    }

    // 7. STACK 和 GLOBAL 不能传给需要heap分配的参数
    if ((source.tag == ProvenanceTag::STACK ||
         source.tag == ProvenanceTag::GLOBAL) &&
        sink.tag == ProvenanceTag::HEAP_MALLOC) {
        return false;
    }

    // 默认：保守允许
    return true;
}

std::string ProvenanceTracker::provenanceTagToString(ProvenanceTag tag) {
    switch (tag) {
        case ProvenanceTag::HEAP_MALLOC:
            return "HEAP_MALLOC";
        case ProvenanceTag::HEAP_CUSTOM:
            return "HEAP_CUSTOM";
        case ProvenanceTag::RETURN_OPAQUE:
            return "RETURN_OPAQUE";
        case ProvenanceTag::PARAM_BORROWED:
            return "PARAM_BORROWED";
        case ProvenanceTag::GLOBAL:
            return "GLOBAL";
        case ProvenanceTag::STACK:
            return "STACK";
        case ProvenanceTag::UNKNOWN:
        default:
            return "UNKNOWN";
    }
}

ProvenanceTag ProvenanceTracker::stringToProvenanceTag(const std::string& str) {
    if (str == "HEAP_MALLOC") return ProvenanceTag::HEAP_MALLOC;
    if (str == "HEAP_CUSTOM") return ProvenanceTag::HEAP_CUSTOM;
    if (str == "RETURN_OPAQUE") return ProvenanceTag::RETURN_OPAQUE;
    if (str == "PARAM_BORROWED") return ProvenanceTag::PARAM_BORROWED;
    if (str == "GLOBAL") return ProvenanceTag::GLOBAL;
    if (str == "STACK") return ProvenanceTag::STACK;
    return ProvenanceTag::UNKNOWN;
}

#ifndef INCLUDE_PROVENANCE_TRACKER_H_
#define INCLUDE_PROVENANCE_TRACKER_H_

#include "Graphs/ICFG.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Function.h>
#include <set>
#include <string>

using namespace SVF;
using namespace llvm;

/**
 * Provenance类型：追踪指针的来源
 * 用于区分不同来源的指针，解决"类型匹配万能插头"问题
 */
enum class ProvenanceTag {
    HEAP_MALLOC,      // malloc/calloc/realloc 分配
    HEAP_CUSTOM,      // 自定义allocator（如cJSON_New, png_create等）
    RETURN_OPAQUE,    // 返回opaque指针（库内部结构）
    PARAM_BORROWED,   // 参数借用（从参数传入的指针）
    GLOBAL,           // 全局变量
    STACK,            // 栈上分配
    UNKNOWN           // 未知来源（保守处理）
};

/**
 * ProvenanceInfo：存储provenance信息
 */
struct ProvenanceInfo {
    ProvenanceTag tag;
    std::string allocator_name;  // 如果是HEAP_CUSTOM，记录allocator名称
    const llvm::Type* allocated_type;  // 分配的类型

    ProvenanceInfo()
        : tag(ProvenanceTag::UNKNOWN),
          allocator_name(""),
          allocated_type(nullptr) {}

    ProvenanceInfo(ProvenanceTag t, const llvm::Type* ty = nullptr)
        : tag(t),
          allocator_name(""),
          allocated_type(ty) {}

    ProvenanceInfo(ProvenanceTag t, const std::string& name, const llvm::Type* ty = nullptr)
        : tag(t),
          allocator_name(name),
          allocated_type(ty) {}

    bool operator==(const ProvenanceInfo& other) const {
        return tag == other.tag &&
               allocator_name == other.allocator_name &&
               allocated_type == other.allocated_type;
    }
};

/**
 * ProvenanceTracker：负责追踪指针的provenance
 * 基于SVF的points-to分析和数据流分析
 */
class ProvenanceTracker {
private:
    BVDataPTAImpl* pta;  // SVF的指针分析
    SVFG* svfg;          // SVF的Value Flow Graph

    // 已知的标准allocator函数
    static std::set<std::string> standard_allocators;

    // 已知的自定义allocator模式（后缀匹配）
    static std::set<std::string> custom_allocator_patterns;

    /**
     * 检查函数是否是标准malloc系列函数
     */
    bool isStandardAllocator(const std::string& func_name) const;

    /**
     * 检查函数是否是自定义allocator
     * 通过命名模式识别（如 *_new, *_create, *_alloc）
     */
    bool isCustomAllocator(const std::string& func_name) const;

    /**
     * 检查返回值是否是opaque指针
     * 通过检查返回类型是否是不完整类型或forward declaration
     */
    bool isOpaquePointer(const llvm::Type* return_type) const;

    /**
     * 通过SVF的points-to分析追踪指针来源
     */
    ProvenanceInfo analyzePointerSource(const llvm::Value* ptr) const;

    /**
     * 分析CallInst的返回值provenance
     */
    ProvenanceInfo analyzeCallReturnValue(const llvm::CallInst* call) const;

    /**
     * 分析参数的provenance
     */
    ProvenanceInfo analyzeParameter(const llvm::Argument* arg) const;

    /**
     * 分析AllocaInst的provenance（栈分配）
     */
    ProvenanceInfo analyzeStackAllocation(const llvm::AllocaInst* alloca) const;

    /**
     * 分析GlobalVariable的provenance
     */
    ProvenanceInfo analyzeGlobalVariable(const llvm::GlobalVariable* gv) const;

public:
    ProvenanceTracker(BVDataPTAImpl* p, SVFG* s) : pta(p), svfg(s) {}

    /**
     * 分析给定Value的provenance
     * 这是主要的对外接口
     */
    ProvenanceInfo analyze(const llvm::Value* value) const;

    /**
     * 分析函数返回值的provenance
     */
    ProvenanceInfo analyzeReturnValue(const llvm::Function* func) const;

    /**
     * 检查两个provenance是否兼容
     * 用于依赖图过滤：返回值provenance是否可以传给参数provenance
     */
    static bool isCompatible(const ProvenanceInfo& source,
                            const ProvenanceInfo& sink);

    /**
     * 将ProvenanceTag转换为字符串（用于调试和JSON输出）
     */
    static std::string provenanceTagToString(ProvenanceTag tag);

    /**
     * 从字符串解析ProvenanceTag
     */
    static ProvenanceTag stringToProvenanceTag(const std::string& str);
};

#endif // INCLUDE_PROVENANCE_TRACKER_H_

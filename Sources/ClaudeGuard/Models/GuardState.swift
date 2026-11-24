import Foundation

enum GuardPhase: Equatable, Sendable {
    case checking
    case wakingUp
    case readySafe
    case readyWithWarning(String)
    case blockedPreFlight(String)
    case guarding(startedAt: Date, presetId: String, controlledPidCount: Int, lastIpVerifiedAt: Date?)
    case killSwitchLocked(reason: String, detail: String, triggeredAt: Date)

    var isGuarding: Bool {
        if case .guarding = self { return true }
        return false
    }

    var isLocked: Bool {
        if case .killSwitchLocked = self { return true }
        return false
    }

    var canLaunch: Bool {
        switch self {
        case .readySafe, .readyWithWarning:
            return true
        case .checking, .wakingUp, .blockedPreFlight, .guarding, .killSwitchLocked:
            return false
        }
    }

    var statusColorCategory: StatusColorCategory {
        switch self {
        case .readySafe, .guarding:
            return .green
        case .checking, .wakingUp, .readyWithWarning:
            return .yellow
        case .blockedPreFlight, .killSwitchLocked:
            return .red
        }
    }
}

enum StatusColorCategory: Equatable, Sendable {
    case green
    case yellow
    case red
}

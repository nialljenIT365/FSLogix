# Define group names
$sourceGroup = "Administrators"
$targetGroups = @(
    "FSLogix Profile Exclude List",
    "FSLogix ODFC Exclude List"
)
# Get members of local Administrators group
$adminMembers = Get-LocalGroupMember -Group $sourceGroup
foreach ($member in $adminMembers) {
    foreach ($targetGroup in $targetGroups) {
        try {
            # Check if member already exists in target group
            $existingMembers = Get-LocalGroupMember -Group $targetGroup -ErrorAction SilentlyContinue
            if ($existingMembers.Name -notcontains $member.Name) {
                Add-LocalGroupMember -Group $targetGroup -Member $member.Name
                Write-Host "Added $($member.Name) to $targetGroup"
            }
            else {
                Write-Host "$($member.Name) already in $targetGroup"
            }
        }
        catch {
            Write-Warning "Failed to process $($member.Name) for $targetGroup - $_"
        }
    }
}
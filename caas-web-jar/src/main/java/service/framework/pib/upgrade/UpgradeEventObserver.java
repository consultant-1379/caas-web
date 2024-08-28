package service.framework.pib.upgrade;

import com.ericsson.oss.itpf.sdk.upgrade.UpgradeEvent;
import com.ericsson.oss.itpf.sdk.upgrade.UpgradePhase;
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

@ApplicationScoped
public class UpgradeEventObserver {

//    @Inject
//    private SystemRecorder systemRecorder;

    @Inject
    private Logger logger;

    public void upgradeNotificationObserver(@Observes final UpgradeEvent event) {

        final UpgradePhase phase = event.getPhase();
        switch (phase) {
            case SERVICE_INSTANCE_UPGRADE_PREPARE:
                logger.info("CaasWeb-Service Upgrade Prepare Stage");
                event.accept("OK");
             //   recordEvent("CaasWeb-Service has accepted upgrade event", phase);
                break;
            case SERVICE_CLUSTER_UPGRADE_PREPARE:
            case SERVICE_CLUSTER_UPGRADE_FAILED:
            case SERVICE_CLUSTER_UPGRADE_FINISHED_SUCCESSFULLY:
            case SERVICE_INSTANCE_UPGRADE_FAILED:
            case SERVICE_INSTANCE_UPGRADE_FINISHED_SUCCESSFULLY:
                logger.info("CaasWeb-Service Upgrade Finished Successfully");
                event.accept("OK");
              //  recordEvent("CaasWeb-Service has accepted upgrade event", phase);
                break;

            default:
                logger.info("CaasWeb-Service has rejected event", phase);
                event.reject("Unexpected UpgradePhase");
             //   recordEvent("CaasWeb-Service has rejected event", phase);
                break;

        }

    }
    /**
     * Records Event
     * @param event The event to record
     */
//    private void recordEvent(final String eventDesc, final UpgradePhase phase) {
//        systemRecorder.recordEvent(eventDesc + " : " + phase.toString(),
//                EventLevel.COARSE,
//                "Upgrade Event : " + phase.toString(),
//                "CaasWeb-Service", "");
//    }

    /**
     * For Unit Test purposes only
     * @param systemRecorder
     */
//    protected void setSystemRecorder(final SystemRecorder systemRecorder) {
//        this.systemRecorder = systemRecorder;
//    }

}

